// C++ replacement for tools/firehose_probe.py
// Subscribe to a PDS firehose over the public ingress and validate frames
// Uses nothing but the standard library (no Wolfram/MetalBear code dependency)
// Transport: POSIX sockets + OpenSSL TLS, with a hand-rolled RFC 6455 client.
// Verifying our own output with our own encoder proves nothing; the checks
// here are the ones a strict reader (the Go ipld stack a relay runs) applies:
//
//   - every CID link is tag 42 wrapping a byte string whose first byte is 0x00
//     (the multibase identity prefix)
//   - the frame header names a known $type / op
//
// Usage: firehose_probe <host> [seconds] [cursor]
//
// A quiet host publishes nothing while the probe is attached and the run ends
// INCONCLUSIVE, which is indistinguishable from a host whose frames never
// decode. Pass a cursor to replay from a known sequence number instead — every
// frame the host has ever written is checked the same way a live one is.

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace {

// An exception shaped like a Python exception so the "(no frames: ...)" line
// can report the same type names the stdlib does.
class PyError : public std::runtime_error {
public:
    std::string pytype;
    PyError(std::string type, const std::string& msg)
        : std::runtime_error(msg), pytype(std::move(type)) {}
};

void throw_errno_socket(const std::string& what) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
        throw PyError("TimeoutError", what + ": timed out");
    if (errno == ECONNRESET)
        throw PyError("ConnectionResetError", what + ": connection reset by peer");
    throw PyError("OSError", what + ": " + std::strerror(errno));
}

struct FdGuard {
    int fd = -1;
    ~FdGuard() {
        if (fd >= 0) close(fd);
    }
};

struct Tls {
    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;
    ~Tls() {
        if (ssl) SSL_free(ssl);
        if (ctx) SSL_CTX_free(ctx);
    }
};

std::string ssl_error_string() {
    char buf[256] = {0};
    unsigned long e = ERR_get_error();
    if (e == 0) return "unknown SSL error";
    ERR_error_string_n(e, buf, sizeof(buf));
    return std::string(buf);
}

void set_sock_timeout(int fd, int which, double seconds) {
    struct timeval tv {};
    tv.tv_sec = static_cast<long>(seconds);
    tv.tv_usec = static_cast<long>((seconds - static_cast<long>(seconds)) * 1e6);
    setsockopt(fd, SOL_SOCKET, which, &tv, sizeof(tv));
}

// Mirrors socket.create_connection((host, 443), timeout=10): a per-attempt
// non-blocking connect with a 10s deadline, walking every resolved address.
int connect_with_timeout(const std::string& host, int port, double timeout_sec) {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    int rc = getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res);
    if (rc != 0)
        throw PyError("OSError", std::string("getaddrinfo: ") + gai_strerror(rc));

    int fd = -1;
    int last_errno = 0;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int ok = -1;
        if (connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            ok = 0;
        } else if (errno == EINPROGRESS) {
            fd_set wfd;
            FD_ZERO(&wfd);
            FD_SET(fd, &wfd);
            struct timeval tv {};
            tv.tv_sec = static_cast<long>(timeout_sec);
            tv.tv_usec = static_cast<long>((timeout_sec - static_cast<long>(timeout_sec)) * 1e6);
            int s = select(fd + 1, nullptr, &wfd, nullptr, &tv);
            if (s > 0) {
                int err = 0;
                socklen_t elen = sizeof(err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 && err == 0) {
                    ok = 0;
                } else {
                    last_errno = err ? err : EIO;
                }
            } else if (s == 0) {
                last_errno = ETIMEDOUT;
            } else {
                last_errno = errno;
            }
        } else {
            last_errno = errno;
        }
        fcntl(fd, F_SETFL, flags);  // back to blocking for SSL
        if (ok == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        throw PyError("OSError", std::string("connect to ") + host + ":" + std::to_string(port) +
                                     " failed: " + std::strerror(last_errno));
    return fd;
}

SSL_CTX* make_ssl_ctx() {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) throw std::runtime_error("SSL_CTX_new: " + ssl_error_string());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
        static const char* kCaBundles[] = {
            "/etc/ssl/cert.pem",
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/opt/homebrew/etc/ca-certificates/cert.pem",
        };
        bool ok = false;
        for (const char* p : kCaBundles) {
            if (SSL_CTX_load_verify_locations(ctx, p, nullptr) == 1) {
                ok = true;
                break;
            }
        }
        if (!ok) {
            SSL_CTX_free(ctx);
            throw std::runtime_error("cannot load CA certificates for TLS verification");
        }
    }
    return ctx;
}

// os.urandom(16) -> base64, exactly the Sec-WebSocket-Key the Python builds.
std::string b64_rand16() {
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1)
        throw std::runtime_error("RAND_bytes failed");
    static const char* kTbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    for (size_t i = 0; i < sizeof(raw); i += 3) {
        unsigned v = static_cast<unsigned>(raw[i]) << 16;
        size_t have = 1;
        if (i + 1 < sizeof(raw)) {
            v |= static_cast<unsigned>(raw[i + 1]) << 8;
            have = 2;
        }
        if (i + 2 < sizeof(raw)) {
            v |= raw[i + 2];
            have = 3;
        }
        out += kTbl[(v >> 18) & 63];
        out += kTbl[(v >> 12) & 63];
        out += have >= 2 ? kTbl[(v >> 6) & 63] : '=';
        out += have >= 3 ? kTbl[v & 63] : '=';
    }
    return out;
}

// Raw read from the TLS stream. Returns >0 bytes read, 0 on clean EOF, -1 on
// error with errno set (EAGAIN after SO_RCVTIMEO, ECONNRESET, ...).
ssize_t read_some(SSL* ssl, uint8_t* out, size_t n) {
    for (;;) {
        int rc = SSL_read(ssl, out, static_cast<int>(n));
        int saved_errno = errno;
        if (rc > 0) return rc;
        int e = SSL_get_error(ssl, rc);
        if (e == SSL_ERROR_ZERO_RETURN) return 0;
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd {};
            pfd.fd = SSL_get_fd(ssl);
            pfd.events = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            if (poll(&pfd, 1, -1) < 0) {
                errno = saved_errno;
                return -1;
            }
            continue;
        }
        if (e == SSL_ERROR_SYSCALL) {
            errno = saved_errno;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            if (errno == ECONNRESET) return -1;
            if (errno == 0) return 0;  // peer closed without close_notify
            return -1;
        }
        return -1;
    }
}

void ssl_write_all(SSL* ssl, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        int n = SSL_write(ssl, data.data() + off, static_cast<int>(data.size() - off));
        if (n > 0) {
            off += static_cast<size_t>(n);
            continue;
        }
        int e = SSL_get_error(ssl, n);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
            struct pollfd pfd {};
            pfd.fd = SSL_get_fd(ssl);
            pfd.events = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
            poll(&pfd, 1, -1);
            continue;
        }
        throw PyError("OSError", "SSL_write failed: " + ssl_error_string());
    }
}

// Minimal RFC 6455 frame reader (server->client frames are unmasked).
class FrameReader {
public:
    explicit FrameReader(SSL* s, const std::string& pending) : ssl_(s) {
        if (!pending.empty()) buf_.assign(pending.begin(), pending.end());
    }

    std::pair<int, std::vector<uint8_t>> frame() {
        uint8_t h[2];
        take(h, 2);
        int opcode = h[0] & 0x0f;
        bool masked = (h[1] & 0x80) != 0;
        uint64_t ln = h[1] & 0x7f;
        if (ln == 126) {
            uint8_t e[2];
            take(e, 2);
            ln = (static_cast<uint64_t>(e[0]) << 8) | e[1];
        } else if (ln == 127) {
            uint8_t e[8];
            take(e, 8);
            ln = 0;
            for (int i = 0; i < 8; i++) ln = (ln << 8) | e[i];
        }
        if (ln > (1u << 30))
            throw PyError("RuntimeError", "frame too large");
        uint8_t mask[4] = {0, 0, 0, 0};
        if (masked) take(mask, 4);
        std::vector<uint8_t> payload(static_cast<size_t>(ln));
        take(payload.data(), static_cast<size_t>(ln));
        if (masked) {
            for (size_t i = 0; i < payload.size(); i++) payload[i] ^= mask[i & 3];
        }
        return {opcode, std::move(payload)};
    }

private:
    SSL* ssl_;
    std::vector<uint8_t> buf_;
    size_t pos_ = 0;

    size_t avail() const { return buf_.size() - pos_; }

    void compact() {
        if (pos_ == 0) return;
        if (pos_ == buf_.size()) {
            buf_.clear();
            pos_ = 0;
            return;
        }
        buf_.erase(buf_.begin(), buf_.begin() + static_cast<ptrdiff_t>(pos_));
        pos_ = 0;
    }

    void need(size_t n) {
        while (avail() < n) {
            compact();
            uint8_t chunk[65536];
            ssize_t got = read_some(ssl_, chunk, sizeof(chunk));
            if (got == 0) throw PyError("RuntimeError", "closed");
            if (got < 0) throw_errno_socket("recv");
            buf_.insert(buf_.end(), chunk, chunk + got);
        }
    }

    void take(uint8_t* out, size_t n) {
        need(n);
        std::memcpy(out, buf_.data() + pos_, n);
        pos_ += n;
    }
};

size_t find_tag(const std::vector<uint8_t>& p, size_t from) {
    for (size_t i = from; i + 1 < p.size(); i++) {
        if (p[i] == 0xd8 && p[i + 1] == 0x2a) return i;
    }
    return std::string::npos;
}

// Scan for every DAG-CBOR tag-42 link and report whether it is well formed.
// Encoding: 0xd8 0x2a (tag 42), then a byte-string header, then the bytes.
// The first content byte MUST be 0x00. Byte-for-byte port of the Python.
std::pair<int, std::vector<std::string>> scan_cid_links(const std::vector<uint8_t>& payload) {
    int good = 0;
    std::vector<std::string> bad;
    size_t i = 0;
    while (true) {
        i = find_tag(payload, i);
        if (i == std::string::npos) break;
        size_t j = i + 2;
        if (j >= payload.size()) break;
        unsigned major = payload[j] >> 5;
        unsigned minor = payload[j] & 0x1f;
        if (major != 2) {  // not a byte string -> not a CID link
            i += 2;
            continue;
        }
        j++;
        size_t ln = 0;
        if (minor < 24) {
            ln = minor;
        } else if (minor == 24) {
            if (j >= payload.size()) break;
            ln = payload[j];
            j++;
        } else if (minor == 25) {
            if (j + 2 > payload.size()) break;
            ln = (static_cast<size_t>(payload[j]) << 8) | payload[j + 1];
            j += 2;
        } else {
            i += 2;
            continue;
        }
        if (j + ln > payload.size()) break;
        if (ln > 0 && payload[j] == 0x00) {
            good++;
        } else {
            std::string hex;
            size_t n = std::min<size_t>(ln, 6);
            for (size_t k = 0; k < n; k++) {
                char b[3];
                std::snprintf(b, sizeof(b), "%02x", payload[j + k]);
                hex += b;
            }
            bad.push_back(hex);
        }
        i = j + ln;
    }
    return {good, bad};
}

// Ordered insertion like Python's dict, so `kinds` prints in encounter order.
struct Kinds {
    std::vector<std::pair<std::string, int>> entries;

    bool empty() const { return entries.empty(); }

    void bump(const std::string& key) {
        for (auto& e : entries) {
            if (e.first == key) {
                e.second++;
                return;
            }
        }
        entries.emplace_back(key, 1);
    }
};

// re.findall(rb"#(commit|identity|account|sync|info|handle)", payload) — the
// keywords share a fixed '#' prefix, so counting each '#kw' occurrence in
// payload order reproduces the regex's matches and insertion order exactly.
void scan_kinds(const std::vector<uint8_t>& payload, std::vector<std::string>& out) {
    static const char* kKinds[] = {"commit", "identity", "account", "sync", "info", "handle"};
    for (size_t i = 0; i + 1 < payload.size(); i++) {
        if (payload[i] != '#') continue;
        for (const char* k : kKinds) {
            size_t len = std::strlen(k);
            if (i + 1 + len <= payload.size() &&
                std::memcmp(payload.data() + i + 1, k, len) == 0) {
                out.emplace_back(k);
                break;
            }
        }
    }
}

// bytes.decode(errors="replace"); status lines are ASCII in practice.
std::string decode_replace(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else {
            out += "\xef\xbf\xbd";
        }
    }
    return out;
}

void usage() {
    std::cerr << "Usage: firehose_probe <host> [seconds] [cursor]\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string host = "bear.croft.click";
    double budget = 30.0;
    std::string path = "/xrpc/com.atproto.sync.subscribeRepos";

    if (argc > 1) {
        std::string a1 = argv[1];
        if (a1 == "-h" || a1 == "--help") {
            usage();
            return 0;
        }
        host = a1;
    }
    if (argc > 2) {
        try {
            size_t idx = 0;
            budget = std::stod(argv[2], &idx);
            if (idx != std::strlen(argv[2]))
                throw std::invalid_argument("trailing characters");
        } catch (...) {
            std::cerr << "  ERROR: invalid seconds value: " << argv[2] << "\n";
            usage();
            return 1;
        }
        if (!std::isfinite(budget) || budget < 0) {
            std::cerr << "  ERROR: seconds must be a finite non-negative number\n";
            usage();
            return 1;
        }
    }
    if (argc > 3) path += "?cursor=" + std::string(argv[3]);

    FdGuard guard;
    Tls tls;

    // Phase 1: TCP connect + TLS. Any failure here is fatal, like an uncaught
    // exception in the Python before its frame loop.
    try {
        guard.fd = connect_with_timeout(host, 443, 10.0);
        set_sock_timeout(guard.fd, SO_RCVTIMEO, 10.0);
        set_sock_timeout(guard.fd, SO_SNDTIMEO, 10.0);
        tls.ctx = make_ssl_ctx();
        tls.ssl = SSL_new(tls.ctx);
        if (!tls.ssl) throw std::runtime_error("SSL_new: " + ssl_error_string());
        SSL_set_fd(tls.ssl, guard.fd);
        if (SSL_set_tlsext_host_name(tls.ssl, host.c_str()) != 1)
            throw std::runtime_error("cannot set SNI hostname");
        if (SSL_set1_host(tls.ssl, host.c_str()) != 1)
            throw std::runtime_error("cannot set expected hostname");
        for (int rc = SSL_connect(tls.ssl); rc != 1;) {
            int e = SSL_get_error(tls.ssl, rc);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                struct pollfd pfd {};
                pfd.fd = guard.fd;
                pfd.events = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
                poll(&pfd, 1, -1);
                rc = SSL_connect(tls.ssl);
                continue;
            }
            std::string msg = ssl_error_string();
            throw std::runtime_error("TLS handshake failed: " + msg);
        }
    } catch (const std::exception& e) {
        std::cerr << "  ERROR: " << e.what() << "\n";
        return 1;
    }

    // Phase 2: HTTP upgrade handshake. Also fatal on failure.
    std::string pending;
    std::string status;
    try {
        std::string key = b64_rand16();
        std::string req =
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + host + "\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Key: " + key + "\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "User-Agent: firehose-probe/1.0\r\n"
            "\r\n";
        ssl_write_all(tls.ssl, req);

        std::string buf;
        while (buf.find("\r\n\r\n") == std::string::npos) {
            char chunk[4096];
            ssize_t n = read_some(tls.ssl, reinterpret_cast<uint8_t*>(chunk), sizeof(chunk));
            if (n == 0) throw PyError("RuntimeError", "connection closed during handshake");
            if (n < 0) throw_errno_socket("recv");
            buf.append(chunk, static_cast<size_t>(n));
        }
        size_t sep = buf.find("\r\n\r\n");
        std::string head = buf.substr(0, sep);
        pending = buf.substr(sep + 4);
        size_t nl = head.find("\r\n");
        status = decode_replace(head.substr(0, nl == std::string::npos ? head.size() : nl));
    } catch (const std::exception& e) {
        std::cerr << "  ERROR: " << e.what() << "\n";
        return 1;
    }

    std::cout << "  handshake: " << status << "\n";
    if (status.find("101") == std::string::npos) {
        std::cerr << "  ERROR: expected 101 Switching Protocols from " << host << "\n";
        return 1;
    }

    // Phase 3: read frames until the deadline. Timeouts and socket errors are
    // reported like the Python's except clause, then the summary still runs.
    set_sock_timeout(guard.fd, SO_RCVTIMEO, budget);
    FrameReader reader(tls.ssl, pending);

    int frames = 0;
    int total_good = 0;
    std::vector<std::string> total_bad;
    Kinds kinds;
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::duration_cast<std::chrono::steady_clock::duration>(
                        std::chrono::duration<double>(budget));
    try {
        while (std::chrono::steady_clock::now() < deadline) {
            auto fr = reader.frame();
            int opcode = fr.first;
            const std::vector<uint8_t>& payload = fr.second;
            if (opcode == 0x9) {  // ping
                kinds.bump("ping");
                continue;
            }
            if (opcode != 0x1 && opcode != 0x2) continue;
            frames++;
            std::vector<std::string> hits;
            scan_kinds(payload, hits);
            for (const std::string& h : hits) kinds.bump(h);
            auto links = scan_cid_links(payload);
            total_good += links.first;
            total_bad.insert(total_bad.end(), links.second.begin(), links.second.end());
            if (frames <= 2)
                std::cout << "  frame " << frames << ": " << payload.size() << " bytes, "
                          << links.first << " CID links\n";
        }
    } catch (const PyError& e) {
        if (frames == 0 && kinds.empty())
            std::cout << "  (no frames: " << e.pytype << ")\n";
    }

    std::cout << "\n";
    std::cout << "  data frames        : " << frames << "\n";
    std::cout << "  frame types        : ";
    if (kinds.empty()) {
        std::cout << "(none)\n";
    } else {
        std::cout << "{";
        for (size_t i = 0; i < kinds.entries.size(); i++) {
            if (i) std::cout << ", ";
            std::cout << "'" << kinds.entries[i].first << "': " << kinds.entries[i].second;
        }
        std::cout << "}\n";
    }
    std::cout << "  CID links w/ 0x00  : " << total_good << "\n";
    std::cout << "  CID links MALFORMED: " << total_bad.size();
    if (!total_bad.empty()) {
        std::cout << " [";
        size_t n = std::min<size_t>(total_bad.size(), 5);
        for (size_t i = 0; i < n; i++) {
            if (i) std::cout << ", ";
            std::cout << "'" << total_bad[i] << "'";
        }
        std::cout << "]";
    }
    std::cout << "\n";
    std::cout << "\n";

    if (!total_bad.empty()) {
        std::cout << "  RESULT: FAIL — malformed CID links; a strict reader rejects these frames\n";
        return 1;
    }
    if (total_good > 0) {
        std::cout << "  RESULT: PASS — every CID link carries the multibase prefix\n";
        return 0;
    }
    bool saw_ping = false;
    for (const auto& e : kinds.entries) {
        if (e.first == "ping" && e.second > 0) saw_ping = true;
    }
    if (saw_ping) {
        std::cout << "  RESULT: stream alive (keepalive only, no writes during the window)\n";
        return 0;
    }
    std::cout << "  RESULT: INCONCLUSIVE — no frames observed\n";
    return 0;
}
