#include "metalbear/video_upload.h"

#include "wolfram/repo/cid.h"

#include <openssl/rand.h>
#include <sqlite3.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr std::time_t kUploadLifetimeSeconds = 24 * 60 * 60;

struct statement_deleter {
    void operator()(sqlite3_stmt *stmt) const noexcept { sqlite3_finalize(stmt); }
};
using statement_ptr = std::unique_ptr<sqlite3_stmt, statement_deleter>;

statement_ptr prepare(sqlite3 *db, const char *sql) {
    sqlite3_stmt *raw = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &raw, nullptr) != SQLITE_OK)
        return {};
    return statement_ptr(raw);
}

bool execute(sqlite3 *db, const char *sql) {
    return sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
}

std::string random_job_id() {
    std::array<unsigned char, 16> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1)
        return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string result = "up-";
    result.reserve(3 + bytes.size() * 2);
    for (unsigned char byte : bytes) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0f]);
    }
    return result;
}

std::string timestamp(std::time_t value) {
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &value);
#else
    gmtime_r(&value, &tm);
#endif
    char text[32]{};
    if (std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &tm) == 0)
        return {};
    return text;
}

void copy_text(char *out, size_t out_size, const char *value) {
    if (!out || out_size == 0) return;
    std::snprintf(out, out_size, "%s", value ? value : "");
}

std::string active_key(const char *job_id, uint32_t part_number) {
    return std::string(job_id) + ":" + std::to_string(part_number);
}

} // namespace

struct metalbear_video_upload_store {
    sqlite3 *db = nullptr;
    std::string parts_directory;
    metalbear_blob_store *blobs = nullptr;
    std::mutex mutex;
    std::unordered_set<std::string> active_parts;

    ~metalbear_video_upload_store() {
        if (db) sqlite3_close(db);
    }
};

struct metalbear_video_part_writer {
    metalbear_video_upload_store *store = nullptr;
    std::string job_id;
    uint32_t part_number = 0;
    uint64_t expected_size = 0;
    uint64_t written = 0;
    std::string temporary_path;
    std::string final_path;
    std::FILE *file = nullptr;
    bool committed = false;
};

namespace {

void expire_sessions_locked(metalbear_video_upload_store *store) {
    auto query = prepare(store->db,
                         "SELECT job_id FROM video_uploads WHERE state=0 AND "
                         "expires_at<=strftime('%s','now');");
    std::vector<std::string> expired;
    if (query) {
        while (sqlite3_step(query.get()) == SQLITE_ROW) {
            const auto *job = sqlite3_column_text(query.get(), 0);
            if (job) expired.emplace_back(reinterpret_cast<const char *>(job));
        }
    }
    (void)execute(store->db,
                  "UPDATE video_uploads SET state=5 WHERE state=0 AND "
                  "expires_at<=strftime('%s','now');");
    for (const auto &job : expired) {
        std::error_code error;
        fs::remove_all(fs::path(store->parts_directory) / job, error);
    }
}

bool load_status_locked(metalbear_video_upload_store *store,
                        const char *job_id,
                        metalbear_video_upload_status *out) {
    /* `job_id` may point into `out` when callers refresh an existing status. */
    const std::string job(job_id ? job_id : "");
    std::memset(out, 0, sizeof(*out));
    auto stmt = prepare(
        store->db,
        "SELECT size_bytes,mime_type,part_size,part_count,expires_at,state,"
        "completed_job_id,cid,failure_reason FROM video_uploads WHERE job_id=?;");
    if (!stmt) return false;
    sqlite3_bind_text(stmt.get(), 1, job.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(stmt.get()) != SQLITE_ROW) return false;
    copy_text(out->job_id, sizeof(out->job_id), job.c_str());
    out->size_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt.get(), 0));
    const auto *mime = sqlite3_column_text(stmt.get(), 1);
    copy_text(out->mime_type, sizeof(out->mime_type),
              reinterpret_cast<const char *>(mime));
    out->part_size_bytes =
        static_cast<uint64_t>(sqlite3_column_int64(stmt.get(), 2));
    out->part_count = static_cast<uint32_t>(sqlite3_column_int(stmt.get(), 3));
    const std::time_t expires =
        static_cast<std::time_t>(sqlite3_column_int64(stmt.get(), 4));
    copy_text(out->expires_at, sizeof(out->expires_at),
              timestamp(expires).c_str());
    out->state = static_cast<metalbear_video_upload_state>(
        sqlite3_column_int(stmt.get(), 5));
    copy_text(out->completed_job_id, sizeof(out->completed_job_id),
              reinterpret_cast<const char *>(sqlite3_column_text(stmt.get(), 6)));
    copy_text(out->cid, sizeof(out->cid),
              reinterpret_cast<const char *>(sqlite3_column_text(stmt.get(), 7)));
    copy_text(out->failure_reason, sizeof(out->failure_reason),
              reinterpret_cast<const char *>(sqlite3_column_text(stmt.get(), 8)));

    auto parts = prepare(store->db,
                         "SELECT part_number FROM video_upload_parts WHERE "
                         "job_id=? ORDER BY part_number;");
    if (!parts) return false;
    sqlite3_bind_text(parts.get(), 1, job.c_str(), -1, SQLITE_TRANSIENT);
    while (out->received_part_count < METALBEAR_VIDEO_MAX_PARTS &&
           sqlite3_step(parts.get()) == SQLITE_ROW) {
        out->received_parts[out->received_part_count++] =
            static_cast<uint32_t>(sqlite3_column_int(parts.get(), 0));
    }
    return true;
}

metalbear_video_upload_result state_result(
    const metalbear_video_upload_status &status) {
    switch (status.state) {
    case METALBEAR_VIDEO_UPLOAD_CREATED:
        return METALBEAR_VIDEO_UPLOAD_OK;
    case METALBEAR_VIDEO_UPLOAD_FINISHING:
        return METALBEAR_VIDEO_UPLOAD_NOT_READY;
    case METALBEAR_VIDEO_UPLOAD_COMPLETED:
        return METALBEAR_VIDEO_UPLOAD_ALREADY_COMPLETED;
    case METALBEAR_VIDEO_UPLOAD_FAILED:
        return METALBEAR_VIDEO_UPLOAD_FAILED_RESULT;
    case METALBEAR_VIDEO_UPLOAD_ABORTED:
        return METALBEAR_VIDEO_UPLOAD_ABORTED_RESULT;
    case METALBEAR_VIDEO_UPLOAD_EXPIRED:
        return METALBEAR_VIDEO_UPLOAD_EXPIRED_RESULT;
    }
    return METALBEAR_VIDEO_UPLOAD_INTERNAL;
}

void limits_locked(metalbear_video_upload_store *store, uint64_t *bytes,
                   uint32_t *videos, uint32_t *open) {
    uint64_t used_bytes = 0;
    uint32_t used_videos = 0;
    uint32_t active = 0;
    auto stmt = prepare(
        store->db,
        "SELECT COALESCE(SUM(size_bytes),0),COUNT(*),"
        "COALESCE(SUM(CASE WHEN state IN (0,1) THEN 1 ELSE 0 END),0) "
        "FROM video_uploads WHERE state IN (0,1,2) AND "
        "created_at>strftime('%s','now')-86400;");
    if (stmt && sqlite3_step(stmt.get()) == SQLITE_ROW) {
        used_bytes =
            static_cast<uint64_t>(sqlite3_column_int64(stmt.get(), 0));
        used_videos = static_cast<uint32_t>(sqlite3_column_int(stmt.get(), 1));
        active = static_cast<uint32_t>(sqlite3_column_int(stmt.get(), 2));
    }
    *bytes = used_bytes >= METALBEAR_VIDEO_DAILY_BYTES
                 ? 0
                 : METALBEAR_VIDEO_DAILY_BYTES - used_bytes;
    *videos = used_videos >= METALBEAR_VIDEO_DAILY_COUNT
                  ? 0
                  : METALBEAR_VIDEO_DAILY_COUNT - used_videos;
    *open = active;
}

bool job_has_active_part(const metalbear_video_upload_store *store,
                         const char *job_id) {
    const std::string prefix = std::string(job_id) + ":";
    for (const auto &key : store->active_parts)
        if (key.rfind(prefix, 0) == 0) return true;
    return false;
}

metalbear_video_upload_result assemble_upload(
    metalbear_video_upload_store *store,
    const metalbear_video_upload_status &status, std::string &assembled,
    std::string &cid_string) {
    const fs::path job_directory =
        fs::path(store->parts_directory) / status.job_id;
    assembled = (job_directory / "assembled.tmp").string();
    std::FILE *output = std::fopen(assembled.c_str(), "wb");
    if (!output) return METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
    wf_cid_hasher *hasher = wf_cid_hasher_new();
    if (!hasher) {
        std::fclose(output);
        std::remove(assembled.c_str());
        return METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
    std::array<unsigned char, 64 * 1024> buffer{};
    uint64_t total = 0;
    bool valid_header = false;
    metalbear_video_upload_result result = METALBEAR_VIDEO_UPLOAD_OK;
    for (uint32_t part = 1; part <= status.part_count; ++part) {
        char filename[32]{};
        std::snprintf(filename, sizeof(filename), "part-%05u", part);
        const std::string path = (job_directory / filename).string();
        std::FILE *input = std::fopen(path.c_str(), "rb");
        if (!input) {
            result = METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
            break;
        }
        while (true) {
            const size_t got = std::fread(buffer.data(), 1, buffer.size(), input);
            if (got > 0) {
                if (total == 0 && got >= 12)
                    valid_header = std::memcmp(buffer.data() + 4, "ftyp", 4) == 0;
                if (total > status.size_bytes || got > status.size_bytes - total ||
                    std::fwrite(buffer.data(), 1, got, output) != got ||
                    wf_cid_hasher_update(hasher, buffer.data(), got) != WF_OK) {
                    result = METALBEAR_VIDEO_UPLOAD_INTERNAL;
                    break;
                }
                total += got;
            }
            if (got < buffer.size()) {
                if (std::ferror(input)) result = METALBEAR_VIDEO_UPLOAD_INTERNAL;
                break;
            }
        }
        if (std::fclose(input) != 0 && result == METALBEAR_VIDEO_UPLOAD_OK)
            result = METALBEAR_VIDEO_UPLOAD_INTERNAL;
        if (result != METALBEAR_VIDEO_UPLOAD_OK) break;
    }
    if (total != status.size_bytes) result = METALBEAR_VIDEO_UPLOAD_INTERNAL;
    const bool flush_failed = std::fflush(output) != 0;
    const bool close_failed = std::fclose(output) != 0;
    if (flush_failed || close_failed) result = METALBEAR_VIDEO_UPLOAD_INTERNAL;
    if (result == METALBEAR_VIDEO_UPLOAD_OK && !valid_header)
        result = METALBEAR_VIDEO_UPLOAD_UNSUPPORTED_CONTENT_TYPE;
    wf_cid cid{};
    if (result == METALBEAR_VIDEO_UPLOAD_OK &&
        wf_cid_hasher_finish_raw(hasher, &cid) == WF_OK) {
        char *encoded = wf_cid_to_string(&cid);
        if (encoded) {
            cid_string = encoded;
            std::free(encoded);
        } else {
            result = METALBEAR_VIDEO_UPLOAD_INTERNAL;
        }
    } else if (result == METALBEAR_VIDEO_UPLOAD_OK) {
        result = METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
    wf_cid_hasher_free(hasher);
    if (result != METALBEAR_VIDEO_UPLOAD_OK) std::remove(assembled.c_str());
    return result;
}

} // namespace

extern "C" {

wf_status metalbear_video_upload_store_open(
    const char *database_path, const char *parts_directory,
    metalbear_blob_store *blobs, metalbear_video_upload_store **out) {
    if (!database_path || !parts_directory || !blobs || !out)
        return WF_ERR_INVALID_ARG;
    *out = nullptr;
    try {
        auto store = std::unique_ptr<metalbear_video_upload_store>(
            new (std::nothrow) metalbear_video_upload_store());
        if (!store) return WF_ERR_ALLOC;
        store->parts_directory = parts_directory;
        store->blobs = blobs;
        std::error_code error;
        fs::create_directories(store->parts_directory, error);
        if (error) return WF_ERR_INTERNAL;
        if (sqlite3_open(database_path, &store->db) != SQLITE_OK)
            return WF_ERR_INTERNAL;
        if (!execute(store->db,
                     "PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;"
                     "PRAGMA busy_timeout=5000;"
                     "CREATE TABLE IF NOT EXISTS video_uploads("
                     "job_id TEXT PRIMARY KEY,size_bytes INTEGER NOT NULL,"
                     "mime_type TEXT NOT NULL,name TEXT,part_size INTEGER NOT NULL,"
                     "part_count INTEGER NOT NULL,expires_at INTEGER NOT NULL,"
                     "state INTEGER NOT NULL,completed_job_id TEXT,cid TEXT,"
                     "failure_reason TEXT,created_at INTEGER NOT NULL);"
                     "CREATE TABLE IF NOT EXISTS video_upload_parts("
                     "job_id TEXT NOT NULL,part_number INTEGER NOT NULL,"
                     "size_bytes INTEGER NOT NULL,PRIMARY KEY(job_id,part_number),"
                     "FOREIGN KEY(job_id) REFERENCES video_uploads(job_id));"
                     "UPDATE video_uploads SET state=0 WHERE state=1;"))
            return WF_ERR_INTERNAL;
        {
            std::lock_guard<std::mutex> lock(store->mutex);
            expire_sessions_locked(store.get());
        }
        *out = store.release();
        return WF_OK;
    } catch (...) {
        return WF_ERR_INTERNAL;
    }
}

void metalbear_video_upload_store_free(metalbear_video_upload_store *store) {
    if (!store) return;
    delete store;
}

metalbear_video_upload_result metalbear_video_upload_start(
    metalbear_video_upload_store *store, uint64_t size_bytes,
    const char *mime_type, const char *name,
    metalbear_video_upload_status *out) {
    if (!store || !mime_type || !out || size_bytes == 0)
        return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    if (size_bytes > METALBEAR_VIDEO_MAX_BYTES)
        return METALBEAR_VIDEO_UPLOAD_TOO_LARGE;
    if (std::strcmp(mime_type, "video/mp4") != 0)
        return METALBEAR_VIDEO_UPLOAD_UNSUPPORTED_CONTENT_TYPE;
    if (name && std::strlen(name) > 256)
        return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    try {
        std::lock_guard<std::mutex> lock(store->mutex);
        expire_sessions_locked(store);
        uint64_t remaining_bytes = 0;
        uint32_t remaining_videos = 0, open = 0;
        limits_locked(store, &remaining_bytes, &remaining_videos, &open);
        if (open >= METALBEAR_VIDEO_MAX_OPEN_UPLOADS)
            return METALBEAR_VIDEO_UPLOAD_TOO_MANY_OPEN;
        if (remaining_videos == 0 || size_bytes > remaining_bytes)
            return METALBEAR_VIDEO_UPLOAD_DAILY_LIMIT;
        const std::string job_id = random_job_id();
        if (job_id.empty()) return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        const uint64_t part_size = METALBEAR_VIDEO_PART_BYTES;
        const uint32_t part_count = static_cast<uint32_t>(
            (size_bytes + part_size - 1) / part_size);
        const std::time_t now = std::time(nullptr);
        auto stmt = prepare(
            store->db,
            "INSERT INTO video_uploads(job_id,size_bytes,mime_type,name,"
            "part_size,part_count,expires_at,state,created_at)"
            "VALUES(?,?,?,?,?,?,?,0,?);");
        if (!stmt) return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        sqlite3_bind_text(stmt.get(), 1, job_id.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt.get(), 2, static_cast<sqlite3_int64>(size_bytes));
        sqlite3_bind_text(stmt.get(), 3, mime_type, -1, SQLITE_TRANSIENT);
        if (name)
            sqlite3_bind_text(stmt.get(), 4, name, -1, SQLITE_TRANSIENT);
        else
            sqlite3_bind_null(stmt.get(), 4);
        sqlite3_bind_int64(stmt.get(), 5, static_cast<sqlite3_int64>(part_size));
        sqlite3_bind_int(stmt.get(), 6, static_cast<int>(part_count));
        sqlite3_bind_int64(stmt.get(), 7,
                           static_cast<sqlite3_int64>(now + kUploadLifetimeSeconds));
        sqlite3_bind_int64(stmt.get(), 8, static_cast<sqlite3_int64>(now));
        if (sqlite3_step(stmt.get()) != SQLITE_DONE)
            return METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
        std::error_code error;
        fs::create_directories(fs::path(store->parts_directory) / job_id, error);
        if (error) {
            auto remove = prepare(store->db,
                                  "DELETE FROM video_uploads WHERE job_id=?;");
            if (remove) {
                sqlite3_bind_text(remove.get(), 1, job_id.c_str(), -1,
                                  SQLITE_TRANSIENT);
                (void)sqlite3_step(remove.get());
            }
            return METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
        }
        return load_status_locked(store, job_id.c_str(), out)
                   ? METALBEAR_VIDEO_UPLOAD_OK
                   : METALBEAR_VIDEO_UPLOAD_INTERNAL;
    } catch (...) {
        return METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
}

metalbear_video_upload_result metalbear_video_upload_part_begin(
    metalbear_video_upload_store *store, const char *job_id,
    uint32_t part_number, uint64_t content_length,
    metalbear_video_part_writer **out) {
    if (!store || !job_id || !out) return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    *out = nullptr;
    std::string registered_key;
    try {
        std::lock_guard<std::mutex> lock(store->mutex);
        expire_sessions_locked(store);
        metalbear_video_upload_status status{};
        if (!load_status_locked(store, job_id, &status))
            return METALBEAR_VIDEO_UPLOAD_NOT_FOUND;
        const auto current = state_result(status);
        if (current != METALBEAR_VIDEO_UPLOAD_OK) return current;
        if (part_number == 0 || part_number > status.part_count)
            return METALBEAR_VIDEO_UPLOAD_INVALID_PART;
        const uint64_t offset =
            static_cast<uint64_t>(part_number - 1) * status.part_size_bytes;
        const uint64_t expected =
            part_number == status.part_count
                ? status.size_bytes - offset
                : status.part_size_bytes;
        if (content_length != expected)
            return METALBEAR_VIDEO_UPLOAD_PART_SIZE_MISMATCH;
        const std::string key = active_key(job_id, part_number);
        if (!store->active_parts.insert(key).second)
            return METALBEAR_VIDEO_UPLOAD_NOT_READY;
        registered_key = key;
        auto writer = std::unique_ptr<metalbear_video_part_writer>(
            new (std::nothrow) metalbear_video_part_writer());
        if (!writer) {
            store->active_parts.erase(key);
            return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        }
        writer->store = store;
        writer->job_id = job_id;
        writer->part_number = part_number;
        writer->expected_size = expected;
        const fs::path directory = fs::path(store->parts_directory) / job_id;
        char final_name[32]{};
        std::snprintf(final_name, sizeof(final_name), "part-%05u", part_number);
        writer->final_path = (directory / final_name).string();
        const std::string nonce = random_job_id();
        if (nonce.empty()) {
            store->active_parts.erase(key);
            return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        }
        writer->temporary_path =
            (directory / (std::string(final_name) + "." + nonce + ".tmp"))
                .string();
        writer->file = std::fopen(writer->temporary_path.c_str(), "wb");
        if (!writer->file) {
            store->active_parts.erase(key);
            return METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
        }
        *out = writer.release();
        return METALBEAR_VIDEO_UPLOAD_OK;
    } catch (...) {
        if (!registered_key.empty()) {
            try {
                std::lock_guard<std::mutex> lock(store->mutex);
                store->active_parts.erase(registered_key);
            } catch (...) {
            }
        }
        return METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
}

metalbear_video_upload_result metalbear_video_upload_part_write(
    metalbear_video_part_writer *writer, const unsigned char *data,
    size_t data_len) {
    if (!writer || !writer->file || (!data && data_len != 0))
        return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    if (writer->written > writer->expected_size ||
        data_len > writer->expected_size - writer->written)
        return METALBEAR_VIDEO_UPLOAD_PART_SIZE_MISMATCH;
    if (data_len && std::fwrite(data, 1, data_len, writer->file) != data_len)
        return METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
    writer->written += data_len;
    return METALBEAR_VIDEO_UPLOAD_OK;
}

metalbear_video_upload_result metalbear_video_upload_part_finish(
    metalbear_video_part_writer *writer) {
    if (!writer || !writer->file)
        return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    if (writer->written != writer->expected_size)
        return METALBEAR_VIDEO_UPLOAD_PART_SIZE_MISMATCH;
    const bool flush_failed = std::fflush(writer->file) != 0;
    const bool close_failed = std::fclose(writer->file) != 0;
    if (flush_failed || close_failed) {
        writer->file = nullptr;
        return METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
    }
    writer->file = nullptr;
    try {
        std::lock_guard<std::mutex> lock(writer->store->mutex);
        metalbear_video_upload_status status{};
        if (!load_status_locked(writer->store, writer->job_id.c_str(), &status))
            return METALBEAR_VIDEO_UPLOAD_NOT_FOUND;
        const auto current = state_result(status);
        if (current != METALBEAR_VIDEO_UPLOAD_OK) return current;
        if (std::rename(writer->temporary_path.c_str(),
                        writer->final_path.c_str()) != 0)
            return METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
        auto stmt = prepare(
            writer->store->db,
            "INSERT OR REPLACE INTO video_upload_parts(job_id,part_number,"
            "size_bytes) VALUES(?,?,?);");
        if (!stmt) return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        sqlite3_bind_text(stmt.get(), 1, writer->job_id.c_str(), -1,
                          SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt.get(), 2, static_cast<int>(writer->part_number));
        sqlite3_bind_int64(stmt.get(), 3,
                           static_cast<sqlite3_int64>(writer->written));
        if (sqlite3_step(stmt.get()) != SQLITE_DONE)
            return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        writer->committed = true;
        return METALBEAR_VIDEO_UPLOAD_OK;
    } catch (...) {
        return METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
}

void metalbear_video_upload_part_free(metalbear_video_part_writer *writer) {
    if (!writer) return;
    if (writer->file) std::fclose(writer->file);
    if (!writer->committed) std::remove(writer->temporary_path.c_str());
    if (writer->store) {
        try {
            std::lock_guard<std::mutex> lock(writer->store->mutex);
            writer->store->active_parts.erase(
                active_key(writer->job_id.c_str(), writer->part_number));
        } catch (...) {
        }
    }
    delete writer;
}

metalbear_video_upload_result metalbear_video_upload_finish(
    metalbear_video_upload_store *store, const char *job_id,
    metalbear_video_upload_status *out, char *detail, size_t detail_size) {
    if (!store || !job_id || !out) return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    if (detail && detail_size) detail[0] = '\0';
    bool marked_finishing = false;
    try {
        metalbear_video_upload_status status{};
        {
            std::lock_guard<std::mutex> lock(store->mutex);
            expire_sessions_locked(store);
            if (!load_status_locked(store, job_id, &status))
                return METALBEAR_VIDEO_UPLOAD_NOT_FOUND;
            if (status.state == METALBEAR_VIDEO_UPLOAD_COMPLETED) {
                *out = status;
                return METALBEAR_VIDEO_UPLOAD_OK;
            }
            const auto current = state_result(status);
            if (current != METALBEAR_VIDEO_UPLOAD_OK) return current;
            if (job_has_active_part(store, job_id))
                return METALBEAR_VIDEO_UPLOAD_NOT_READY;
            if (status.received_part_count != status.part_count) {
                if (detail && detail_size) {
                    std::string missing = "missing parts:";
                    size_t index = 0;
                    for (uint32_t part = 1; part <= status.part_count; ++part) {
                        if (index < status.received_part_count &&
                            status.received_parts[index] == part) {
                            ++index;
                        } else {
                            missing += " " + std::to_string(part);
                        }
                    }
                    copy_text(detail, detail_size, missing.c_str());
                }
                return METALBEAR_VIDEO_UPLOAD_MISSING_PARTS;
            }
            auto update = prepare(store->db,
                                  "UPDATE video_uploads SET state=1 WHERE "
                                  "job_id=? AND state=0;");
            if (!update) return METALBEAR_VIDEO_UPLOAD_INTERNAL;
            sqlite3_bind_text(update.get(), 1, job_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(update.get()) != SQLITE_DONE ||
                sqlite3_changes(store->db) != 1)
                return METALBEAR_VIDEO_UPLOAD_NOT_READY;
            marked_finishing = true;
        }

        std::string assembled, cid;
        metalbear_video_upload_result result =
            assemble_upload(store, status, assembled, cid);
        if (result == METALBEAR_VIDEO_UPLOAD_OK &&
            metalbear_blob_store_put_file(store->blobs, cid.c_str(),
                                          status.mime_type, assembled.c_str(),
                                          static_cast<size_t>(status.size_bytes)) !=
                WF_OK)
            result = METALBEAR_VIDEO_UPLOAD_SERVICE_OVERLOADED;
        std::remove(assembled.c_str());

        std::lock_guard<std::mutex> lock(store->mutex);
        if (result == METALBEAR_VIDEO_UPLOAD_OK) {
            const std::string completed =
                "vid-" + std::to_string(std::time(nullptr)) + "-" + cid + "-" +
                std::to_string(status.size_bytes);
            auto update = prepare(
                store->db,
                "UPDATE video_uploads SET state=2,completed_job_id=?,cid=?,"
                "failure_reason=NULL WHERE job_id=?;");
            if (!update) return METALBEAR_VIDEO_UPLOAD_INTERNAL;
            sqlite3_bind_text(update.get(), 1, completed.c_str(), -1,
                              SQLITE_TRANSIENT);
            sqlite3_bind_text(update.get(), 2, cid.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(update.get(), 3, job_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(update.get()) != SQLITE_DONE)
                return METALBEAR_VIDEO_UPLOAD_INTERNAL;
            std::error_code error;
            fs::remove_all(fs::path(store->parts_directory) / job_id, error);
        } else if (result == METALBEAR_VIDEO_UPLOAD_UNSUPPORTED_CONTENT_TYPE) {
            auto update = prepare(
                store->db,
                "UPDATE video_uploads SET state=3,failure_reason="
                "'assembled object is not video/mp4' WHERE job_id=?;");
            if (update) {
                sqlite3_bind_text(update.get(), 1, job_id, -1, SQLITE_TRANSIENT);
                (void)sqlite3_step(update.get());
            }
        } else {
            auto update = prepare(store->db,
                                  "UPDATE video_uploads SET state=0 WHERE "
                                  "job_id=? AND state=1;");
            if (update) {
                sqlite3_bind_text(update.get(), 1, job_id, -1, SQLITE_TRANSIENT);
                (void)sqlite3_step(update.get());
            }
        }
        if (!load_status_locked(store, job_id, out))
            return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        return result;
    } catch (...) {
        if (marked_finishing) {
            try {
                std::lock_guard<std::mutex> lock(store->mutex);
                auto update = prepare(store->db,
                                      "UPDATE video_uploads SET state=0 WHERE "
                                      "job_id=? AND state=1;");
                if (update) {
                    sqlite3_bind_text(update.get(), 1, job_id, -1,
                                      SQLITE_TRANSIENT);
                    (void)sqlite3_step(update.get());
                }
            } catch (...) {
            }
        }
        return METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
}

metalbear_video_upload_result metalbear_video_upload_abort(
    metalbear_video_upload_store *store, const char *job_id,
    metalbear_video_upload_status *out) {
    if (!store || !job_id || !out) return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    try {
        std::lock_guard<std::mutex> lock(store->mutex);
        expire_sessions_locked(store);
        if (!load_status_locked(store, job_id, out))
            return METALBEAR_VIDEO_UPLOAD_NOT_FOUND;
        if (out->state == METALBEAR_VIDEO_UPLOAD_FINISHING ||
            job_has_active_part(store, job_id))
            return METALBEAR_VIDEO_UPLOAD_NOT_READY;
        if (out->state == METALBEAR_VIDEO_UPLOAD_CREATED) {
            auto update = prepare(store->db,
                                  "UPDATE video_uploads SET state=4 WHERE "
                                  "job_id=? AND state=0;");
            if (!update) return METALBEAR_VIDEO_UPLOAD_INTERNAL;
            sqlite3_bind_text(update.get(), 1, job_id, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(update.get()) != SQLITE_DONE)
                return METALBEAR_VIDEO_UPLOAD_INTERNAL;
            std::error_code error;
            fs::remove_all(fs::path(store->parts_directory) / job_id, error);
            auto remove = prepare(store->db,
                                  "DELETE FROM video_upload_parts WHERE job_id=?;");
            if (remove) {
                sqlite3_bind_text(remove.get(), 1, job_id, -1, SQLITE_TRANSIENT);
                (void)sqlite3_step(remove.get());
            }
            if (!load_status_locked(store, job_id, out))
                return METALBEAR_VIDEO_UPLOAD_INTERNAL;
        }
        return METALBEAR_VIDEO_UPLOAD_OK;
    } catch (...) {
        return METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
}

metalbear_video_upload_result metalbear_video_upload_get_status(
    metalbear_video_upload_store *store, const char *job_id,
    metalbear_video_upload_status *out) {
    if (!store || !job_id || !out) return METALBEAR_VIDEO_UPLOAD_INVALID_REQUEST;
    try {
        std::lock_guard<std::mutex> lock(store->mutex);
        expire_sessions_locked(store);
        return load_status_locked(store, job_id, out)
                   ? METALBEAR_VIDEO_UPLOAD_OK
                   : METALBEAR_VIDEO_UPLOAD_NOT_FOUND;
    } catch (...) {
        return METALBEAR_VIDEO_UPLOAD_INTERNAL;
    }
}

void metalbear_video_upload_get_limits(metalbear_video_upload_store *store,
                                       uint64_t *remaining_bytes,
                                       uint32_t *remaining_videos,
                                       uint32_t *open_uploads) {
    if (!remaining_bytes || !remaining_videos || !open_uploads) return;
    *remaining_bytes = 0;
    *remaining_videos = 0;
    *open_uploads = 0;
    if (!store) return;
    try {
        std::lock_guard<std::mutex> lock(store->mutex);
        expire_sessions_locked(store);
        limits_locked(store, remaining_bytes, remaining_videos, open_uploads);
    } catch (...) {
    }
}

} // extern "C"
