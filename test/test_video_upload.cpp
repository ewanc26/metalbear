#include "metalbear/repo/blob_store.h"
#include "metalbear/video_upload.h"
#include "test.h"

#include <sqlite3.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

#ifndef _WIN32
#include <sys/resource.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

static const std::array<unsigned char, 16> kTinyMp4 = {
    0, 0, 0, 16, 'f', 't', 'y', 'p', 'i', 's', 'o', 'm', 0, 0, 0, 0};

struct fixture {
    std::string root;
    metalbear_blob_store *blobs = nullptr;
    metalbear_video_upload_store *uploads = nullptr;

    explicit fixture(const char *suffix) {
#ifndef _WIN32
        (void)suffix;
        char path[] = "/tmp/metalbear-video-XXXXXX";
        char *made = mkdtemp(path);
        if (made) root = made;
#else
        root = std::string("metalbear-video-") + suffix;
#endif
        std::error_code error;
        fs::create_directories(root, error);
        fs::create_directories(fs::path(root) / "blobs", error);
        blobs = metalbear_blob_store_new((fs::path(root) / "blobs").c_str());
        if (blobs)
            (void)metalbear_video_upload_store_open(
                (fs::path(root) / "uploads.sqlite3").c_str(),
                (fs::path(root) / "parts").c_str(), blobs, &uploads);
    }

    ~fixture() {
        metalbear_video_upload_store_free(uploads);
        metalbear_blob_store_free(blobs);
        std::error_code error;
        fs::remove_all(root, error);
    }
};

static metalbear_video_upload_result put_part(
    metalbear_video_upload_store *store, const char *job_id,
    uint32_t part_number, const unsigned char *data, size_t size) {
    metalbear_video_part_writer *writer = nullptr;
    metalbear_video_upload_result result = metalbear_video_upload_part_begin(
        store, job_id, part_number, size, &writer);
    if (result == METALBEAR_VIDEO_UPLOAD_OK) {
        const size_t split = size / 3;
        result = metalbear_video_upload_part_write(writer, data, split);
        if (result == METALBEAR_VIDEO_UPLOAD_OK)
            result = metalbear_video_upload_part_write(writer, data + split,
                                                        size - split);
        if (result == METALBEAR_VIDEO_UPLOAD_OK)
            result = metalbear_video_upload_part_finish(writer);
    }
    metalbear_video_upload_part_free(writer);
    return result;
}

static void test_happy_path_and_idempotence() {
    fixture f("-happy");
    WF_CHECK(f.blobs != nullptr && f.uploads != nullptr);
    metalbear_video_upload_status status{};
    WF_CHECK(metalbear_video_upload_start(f.uploads, kTinyMp4.size(),
                                          "video/mp4", "tiny.mp4", &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(status.part_count == 1);
    WF_CHECK(status.part_size_bytes == METALBEAR_VIDEO_PART_BYTES);

    metalbear_video_part_writer *wrong = nullptr;
    WF_CHECK(metalbear_video_upload_part_begin(
                 f.uploads, status.job_id, 1, kTinyMp4.size() - 1, &wrong) ==
             METALBEAR_VIDEO_UPLOAD_PART_SIZE_MISMATCH);
    WF_CHECK(wrong == nullptr);

    /* A disconnected part is never recorded and can be retried safely. */
    metalbear_video_part_writer *interrupted = nullptr;
    WF_CHECK(metalbear_video_upload_part_begin(
                 f.uploads, status.job_id, 1, kTinyMp4.size(), &interrupted) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(metalbear_video_upload_part_write(interrupted, kTinyMp4.data(), 4) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    metalbear_video_upload_part_free(interrupted);
    WF_CHECK(metalbear_video_upload_get_status(f.uploads, status.job_id,
                                               &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(status.received_part_count == 0);

    WF_CHECK(put_part(f.uploads, status.job_id, 1, kTinyMp4.data(),
                      kTinyMp4.size()) == METALBEAR_VIDEO_UPLOAD_OK);
    /* Re-sending a complete part replaces it and retains one receipt. */
    WF_CHECK(put_part(f.uploads, status.job_id, 1, kTinyMp4.data(),
                      kTinyMp4.size()) == METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(metalbear_video_upload_get_status(f.uploads, status.job_id,
                                               &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(status.received_part_count == 1 && status.received_parts[0] == 1);
    char detail[256]{};
    WF_CHECK(metalbear_video_upload_finish(f.uploads, status.job_id, &status,
                                           detail, sizeof(detail)) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(status.state == METALBEAR_VIDEO_UPLOAD_COMPLETED);
    WF_CHECK(status.completed_job_id[0] != '\0' && status.cid[0] != '\0');

    unsigned char *stored = nullptr;
    size_t stored_size = 0;
    char *mime = nullptr;
    WF_CHECK(metalbear_blob_store_get(f.blobs, status.cid, &stored,
                                      &stored_size, &mime) == WF_OK);
    WF_CHECK(stored_size == kTinyMp4.size());
    WF_CHECK(stored && std::memcmp(stored, kTinyMp4.data(), stored_size) == 0);
    WF_CHECK(mime && std::strcmp(mime, "video/mp4") == 0);
    std::free(stored);
    std::free(mime);

    char completed_id[257]{};
    std::snprintf(completed_id, sizeof(completed_id), "%s",
                  status.completed_job_id);
    WF_CHECK(metalbear_video_upload_finish(f.uploads, status.job_id, &status,
                                           detail, sizeof(detail)) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(std::strcmp(completed_id, status.completed_job_id) == 0);
}

static void test_ownership_abort_and_recovery() {
    fixture first("-owner-a");
    fixture second("-owner-b");
    metalbear_video_upload_status status{};
    WF_CHECK(metalbear_video_upload_start(first.uploads, kTinyMp4.size(),
                                          "video/mp4", nullptr, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    char job_id[257]{};
    std::snprintf(job_id, sizeof(job_id), "%s", status.job_id);
    WF_CHECK(metalbear_video_upload_get_status(second.uploads, job_id, &status) ==
             METALBEAR_VIDEO_UPLOAD_NOT_FOUND);
    WF_CHECK(metalbear_video_upload_abort(first.uploads, job_id, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(status.state == METALBEAR_VIDEO_UPLOAD_ABORTED);
    WF_CHECK(metalbear_video_upload_abort(first.uploads, job_id, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);

    WF_CHECK(metalbear_video_upload_start(first.uploads, kTinyMp4.size(),
                                          "video/mp4", nullptr, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    std::snprintf(job_id, sizeof(job_id), "%s", status.job_id);
    metalbear_video_upload_store_free(first.uploads);
    first.uploads = nullptr;
    sqlite3 *db = nullptr;
    WF_CHECK(sqlite3_open((fs::path(first.root) / "uploads.sqlite3").c_str(),
                          &db) == SQLITE_OK);
    std::string force_finishing =
        "UPDATE video_uploads SET state=1 WHERE job_id='" +
        std::string(job_id) + "';";
    WF_CHECK(sqlite3_exec(db, force_finishing.c_str(), nullptr, nullptr,
                          nullptr) == SQLITE_OK);
    sqlite3_close(db);
    WF_CHECK(metalbear_video_upload_store_open(
                 (fs::path(first.root) / "uploads.sqlite3").c_str(),
                 (fs::path(first.root) / "parts").c_str(), first.blobs,
                 &first.uploads) == WF_OK);
    WF_CHECK(metalbear_video_upload_get_status(first.uploads, job_id, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(status.state == METALBEAR_VIDEO_UPLOAD_CREATED);
}

static void test_missing_and_invalid_content() {
    fixture f("-errors");
    metalbear_video_upload_status status{};
    WF_CHECK(metalbear_video_upload_start(
                 f.uploads, METALBEAR_VIDEO_PART_BYTES + kTinyMp4.size(),
                 "video/mp4", nullptr, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    char detail[256]{};
    WF_CHECK(metalbear_video_upload_finish(f.uploads, status.job_id, &status,
                                           detail, sizeof(detail)) ==
             METALBEAR_VIDEO_UPLOAD_MISSING_PARTS);
    WF_CHECK(std::strstr(detail, "1") && std::strstr(detail, "2"));
    WF_CHECK(metalbear_video_upload_abort(f.uploads, status.job_id, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);

    std::array<unsigned char, 16> invalid{};
    WF_CHECK(metalbear_video_upload_start(f.uploads, invalid.size(),
                                          "video/mp4", nullptr, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(put_part(f.uploads, status.job_id, 1, invalid.data(),
                      invalid.size()) == METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(metalbear_video_upload_finish(f.uploads, status.job_id, &status,
                                           detail, sizeof(detail)) ==
             METALBEAR_VIDEO_UPLOAD_UNSUPPORTED_CONTENT_TYPE);
    WF_CHECK(status.state == METALBEAR_VIDEO_UPLOAD_FAILED);
}

static void test_quota_reservations() {
    fixture open_cap("-open-cap");
    std::array<metalbear_video_upload_status,
               METALBEAR_VIDEO_MAX_OPEN_UPLOADS>
        sessions{};
    for (auto &status : sessions)
        WF_CHECK(metalbear_video_upload_start(
                     open_cap.uploads, kTinyMp4.size(), "video/mp4", nullptr,
                     &status) == METALBEAR_VIDEO_UPLOAD_OK);
    metalbear_video_upload_status rejected{};
    WF_CHECK(metalbear_video_upload_start(
                 open_cap.uploads, kTinyMp4.size(), "video/mp4", nullptr,
                 &rejected) == METALBEAR_VIDEO_UPLOAD_TOO_MANY_OPEN);
    WF_CHECK(metalbear_video_upload_abort(open_cap.uploads, sessions[0].job_id,
                                          &sessions[0]) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(metalbear_video_upload_start(
                 open_cap.uploads, kTinyMp4.size(), "video/mp4", nullptr,
                 &rejected) == METALBEAR_VIDEO_UPLOAD_OK);

    fixture daily("-daily-cap");
    for (int i = 0; i < 3; ++i)
        WF_CHECK(metalbear_video_upload_start(
                     daily.uploads, METALBEAR_VIDEO_MAX_BYTES, "video/mp4",
                     nullptr, &rejected) == METALBEAR_VIDEO_UPLOAD_OK);
    WF_CHECK(metalbear_video_upload_start(
                 daily.uploads, METALBEAR_VIDEO_MAX_BYTES, "video/mp4", nullptr,
                 &rejected) == METALBEAR_VIDEO_UPLOAD_DAILY_LIMIT);
    uint64_t bytes = 0;
    uint32_t videos = 0, open = 0;
    metalbear_video_upload_get_limits(daily.uploads, &bytes, &videos, &open);
    WF_CHECK(bytes == METALBEAR_VIDEO_DAILY_BYTES -
                          3 * METALBEAR_VIDEO_MAX_BYTES);
    WF_CHECK(videos == METALBEAR_VIDEO_DAILY_COUNT - 3);
    WF_CHECK(open == 3);
}

static void optional_large_rss_fixture() {
    if (!std::getenv("METALBEAR_RUN_LARGE_VIDEO_TEST")) return;
    fixture f("-large");
    metalbear_video_upload_status status{};
    WF_CHECK(metalbear_video_upload_start(f.uploads, METALBEAR_VIDEO_MAX_BYTES,
                                          "video/mp4", nullptr, &status) ==
             METALBEAR_VIDEO_UPLOAD_OK);
    std::array<unsigned char, 64 * 1024> buffer{};
    std::memcpy(buffer.data() + 4, "ftyp", 4);
    for (uint32_t part = 1; part <= status.part_count; ++part) {
        metalbear_video_part_writer *writer = nullptr;
        WF_CHECK(metalbear_video_upload_part_begin(
                     f.uploads, status.job_id, part,
                     METALBEAR_VIDEO_PART_BYTES, &writer) ==
                 METALBEAR_VIDEO_UPLOAD_OK);
        uint64_t left = METALBEAR_VIDEO_PART_BYTES;
        while (left > 0) {
            const size_t chunk =
                left < buffer.size() ? static_cast<size_t>(left) : buffer.size();
            WF_CHECK(metalbear_video_upload_part_write(writer, buffer.data(),
                                                       chunk) ==
                     METALBEAR_VIDEO_UPLOAD_OK);
            left -= chunk;
            if (part == 1) std::memset(buffer.data(), 0, buffer.size());
        }
        WF_CHECK(metalbear_video_upload_part_finish(writer) ==
                 METALBEAR_VIDEO_UPLOAD_OK);
        metalbear_video_upload_part_free(writer);
    }
    char detail[256]{};
    WF_CHECK(metalbear_video_upload_finish(f.uploads, status.job_id, &status,
                                           detail, sizeof(detail)) ==
             METALBEAR_VIDEO_UPLOAD_OK);
#ifndef _WIN32
    struct rusage usage {};
    WF_CHECK(getrusage(RUSAGE_SELF, &usage) == 0);
#ifdef __APPLE__
    const long peak_mb = usage.ru_maxrss / (1024 * 1024);
#else
    const long peak_mb = usage.ru_maxrss / 1024;
#endif
    WF_CHECK(peak_mb < 96);
#endif
}

int main() {
    test_happy_path_and_idempotence();
    test_ownership_abort_and_recovery();
    test_missing_and_invalid_content();
    test_quota_reservations();
    optional_large_rss_fixture();
    WF_TEST_SUMMARY();
}
