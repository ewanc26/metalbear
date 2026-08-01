// C++ replacement for tools/verify_repo_car.py
// Independently verify a MetalBear repo CAR against the key published in PLC.
//
// Uses neither MetalBear nor Wolfram: CAR framing, DAG-CBOR re-encoding, and
// secp256k1 verification are all done here, so a pass means a third party
// (relay, AppView) would accept the repo. Self-contained: OpenSSL + libcurl
// only (no libsecp256k1 dependency).
//
// Byte-for-byte port of the Python reference. Every validation failure prints
// the Python's error text to stderr and exits non-zero; success prints the
// Python's summary lines to stdout.
//
// Usage: verify_repo_car <car_path> <did>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <curl/curl.h>

#include <openssl/evp.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

namespace {

const std::string kPlcUrl = "https://plc.directory";

// ---------------------------------------------------------------------------
// Base32 (RFC 4648, lowercase, no padding) and base58btc (Bitcoin alphabet).
// ---------------------------------------------------------------------------

std::string base32_lower_nopad(const std::string& in) {
    static const char* kAlphabet = "abcdefghijklmnopqrstuvwxyz234567";
    std::string out;
    uint32_t buffer = 0;
    int bits = 0;
    for (unsigned char c : in) {
        buffer = (buffer << 8) | c;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out.push_back(kAlphabet[(buffer >> bits) & 0x1f]);
        }
    }
    if (bits > 0) out.push_back(kAlphabet[(buffer << (5 - bits)) & 0x1f]);
    return out;
}

// Python's b58decode: base58btc with the '1'->0x00 padding logic.
std::string b58decode(const std::string& s, std::string& err) {
    static const char* kAlphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    size_t pad = 0;
    while (pad < s.size() && s[pad] == '1') pad++;
    std::vector<uint8_t> num;  // big-endian digits
    for (size_t k = pad; k < s.size(); k++) {
        const char* q = std::strchr(kAlphabet, s[k]);
        if (q == nullptr) {
            err = "invalid base58 character";
            return {};
        }
        int carry = static_cast<int>(q - kAlphabet);
        for (size_t j = num.size(); j-- > 0;) {
            carry += static_cast<int>(num[j]) * 58;
            num[j] = static_cast<uint8_t>(carry & 0xff);
            carry >>= 8;
        }
        while (carry) {
            num.insert(num.begin(), static_cast<uint8_t>(carry & 0xff));
            carry >>= 8;
        }
    }
    std::string out(pad, '\0');
    out.append(num.begin(), num.end());
    return out;
}

// ---------------------------------------------------------------------------
// Unsigned varint (LEB128) used by the CAR framing.
// ---------------------------------------------------------------------------

bool uvarint(const uint8_t* buf, size_t limit, size_t& i, uint64_t& x, std::string& err) {
    x = 0;
    unsigned shift = 0;
    while (true) {
        if (i >= limit) {
            err = "unexpected end of CAR data";
            return false;
        }
        uint8_t b = buf[i++];
        if (shift < 63) {
            x |= static_cast<uint64_t>(b & 0x7F) << shift;
        } else {
            if ((b & 0xFE) != 0) {
                err = "varint overflow";
                return false;
            }
            x |= static_cast<uint64_t>(b & 0x7F) << 63;
        }
        if (!(b & 0x80)) return true;
        if (shift >= 63) {
            err = "varint overflow";
            return false;
        }
        shift += 7;
    }
}

// ---------------------------------------------------------------------------
// Minimal DAG-CBOR (RFC 8949) decoder + canonical re-encoder.
//
// The signature is over the canonical re-encoding of the commit with "sig"
// removed (cbor2.dumps(canonical=True)). The re-encoder therefore must match
// cbor2's canonical form byte for byte: minimal integer/length headers, and
// map keys sorted by (encoded key length, then bytewise).
// ---------------------------------------------------------------------------

struct CBORValue {
    enum class T { Int, Bytes, Text, Array, Map, Tag, Simple };
    T t = T::Int;
    int64_t i = 0;
    std::string bytes;
    std::vector<CBORValue> array;
    std::vector<std::pair<CBORValue, CBORValue>> map;
    uint64_t tag = 0;
    std::vector<CBORValue> tagvals;
    bool is_null = false;
    bool is_bool = false;
    bool boolv = false;

    static CBORValue intval(int64_t v) {
        CBORValue x;
        x.t = T::Int;
        x.i = v;
        return x;
    }
    static CBORValue str(T kind, const char* s, size_t n) {
        CBORValue x;
        x.t = kind;
        x.bytes.assign(s, n);
        return x;
    }
    static CBORValue make_array(uint64_t cap) {
        CBORValue x;
        x.t = T::Array;
        x.array.reserve(static_cast<size_t>(cap));
        return x;
    }
    static CBORValue make_map() {
        CBORValue x;
        x.t = T::Map;
        return x;
    }
    static CBORValue tagged(uint64_t t, CBORValue v) {
        CBORValue x;
        x.t = T::Tag;
        x.tag = t;
        x.tagvals.push_back(std::move(v));
        return x;
    }
    static CBORValue null() {
        CBORValue x;
        x.t = T::Simple;
        x.is_null = true;
        return x;
    }
    static CBORValue make_bool(bool b) {
        CBORValue x;
        x.t = T::Simple;
        x.is_bool = true;
        x.boolv = b;
        return x;
    }
};

class CBORDecoder {
public:
    CBORDecoder(const uint8_t* p, size_t n, std::string& err) : p_(p), n_(n), err_(err) {}

    bool decode(CBORValue& v) {
        if (!item(v)) return false;
        return i_ == n_;
    }

private:
    const uint8_t* p_;
    size_t n_;
    size_t i_ = 0;
    std::string& err_;

    bool fail(const std::string& msg) {
        if (err_.empty()) err_ = msg;
        return false;
    }

    bool u8(uint8_t& out) {
        if (i_ >= n_) return fail("unexpected end of data");
        out = p_[i_++];
        return true;
    }

    bool read_be(size_t width, uint64_t& out) {
        if (i_ + width > n_) return fail("unexpected end of data");
        uint64_t v = 0;
        for (size_t k = 0; k < width; k++) v = (v << 8) | p_[i_++];
        out = v;
        return true;
    }

    bool aux(int ai, uint64_t& out) {
        if (ai < 24) {
            out = static_cast<uint64_t>(ai);
            return true;
        }
        switch (ai) {
        case 24: {
            uint8_t b;
            if (!u8(b)) return false;
            out = b;
            return true;
        }
        case 25: return read_be(2, out);
        case 26: return read_be(4, out);
        case 27: return read_be(8, out);
        default: return fail("reserved additional info");
        }
    }

    bool item(CBORValue& v) {
        uint8_t b;
        if (!u8(b)) return false;
        int major = b >> 5;
        int ai = b & 0x1f;
        switch (major) {
        case 0: {
            uint64_t a;
            if (!aux(ai, a)) return false;
            if (a > static_cast<uint64_t>(INT64_MAX)) return fail("integer out of range");
            v = CBORValue::intval(static_cast<int64_t>(a));
            return true;
        }
        case 1: {
            uint64_t a;
            if (!aux(ai, a)) return false;
            if (a > static_cast<uint64_t>(INT64_MAX)) return fail("integer out of range");
            v = CBORValue::intval(-1 - static_cast<int64_t>(a));
            return true;
        }
        case 2:
        case 3: {
            if (ai == 31) return fail("indefinite-length strings not supported");
            uint64_t len;
            if (!aux(ai, len)) return false;
            if (i_ + len > n_) return fail("truncated string");
            v = CBORValue::str(major == 2 ? CBORValue::T::Bytes : CBORValue::T::Text,
                               reinterpret_cast<const char*>(p_ + i_), static_cast<size_t>(len));
            i_ += static_cast<size_t>(len);
            return true;
        }
        case 4: {
            if (ai == 31) return fail("indefinite-length arrays not supported");
            uint64_t len;
            if (!aux(ai, len)) return false;
            if (len > n_ - i_) return fail("array length exceeds data");
            v = CBORValue::make_array(len);
            for (uint64_t k = 0; k < len; k++) {
                CBORValue e;
                if (!item(e)) return false;
                v.array.push_back(std::move(e));
            }
            return true;
        }
        case 5: {
            if (ai == 31) return fail("indefinite-length maps not supported");
            uint64_t len;
            if (!aux(ai, len)) return false;
            if (len > n_ - i_) return fail("map length exceeds data");
            v = CBORValue::make_map();
            for (uint64_t k = 0; k < len; k++) {
                CBORValue key, val;
                if (!item(key)) return false;
                if (!item(val)) return false;
                v.map.emplace_back(std::move(key), std::move(val));
            }
            return true;
        }
        case 6: {
            uint64_t tag;
            if (!aux(ai, tag)) return false;
            CBORValue inner;
            if (!item(inner)) return false;
            v = CBORValue::tagged(tag, std::move(inner));
            return true;
        }
        case 7:
            if (ai == 20) {
                v = CBORValue::make_bool(true);
                return true;
            }
            if (ai == 21) {
                v = CBORValue::make_bool(false);
                return true;
            }
            if (ai == 22) {
                v = CBORValue::null();
                return true;
            }
            if (ai == 23) {
                v = CBORValue::null();
                return true;
            }
            return fail("unsupported simple value or float");
        }
        return fail("unknown major type");
    }
};

void cbor_enc_head(std::string& out, int major, uint64_t val) {
    if (val < 24) {
        out.push_back(static_cast<char>((major << 5) | static_cast<int>(val)));
    } else if (val < 0x100) {
        out.push_back(static_cast<char>((major << 5) | 24));
        out.push_back(static_cast<char>(val));
    } else if (val < 0x10000) {
        out.push_back(static_cast<char>((major << 5) | 25));
        out.push_back(static_cast<char>(val >> 8));
        out.push_back(static_cast<char>(val));
    } else if (val < 0x100000000ULL) {
        out.push_back(static_cast<char>((major << 5) | 26));
        for (int s = 24; s >= 0; s -= 8) out.push_back(static_cast<char>(val >> s));
    } else {
        out.push_back(static_cast<char>((major << 5) | 27));
        for (int s = 56; s >= 0; s -= 8) out.push_back(static_cast<char>(val >> s));
    }
}

void cbor_encode(const CBORValue& v, std::string& out) {
    switch (v.t) {
    case CBORValue::T::Int:
        if (v.i >= 0) {
            cbor_enc_head(out, 0, static_cast<uint64_t>(v.i));
        } else {
            cbor_enc_head(out, 1, static_cast<uint64_t>(-1 - v.i));
        }
        break;
    case CBORValue::T::Bytes:
        cbor_enc_head(out, 2, v.bytes.size());
        out += v.bytes;
        break;
    case CBORValue::T::Text:
        cbor_enc_head(out, 3, v.bytes.size());
        out += v.bytes;
        break;
    case CBORValue::T::Array:
        cbor_enc_head(out, 4, v.array.size());
        for (const auto& e : v.array) cbor_encode(e, out);
        break;
    case CBORValue::T::Map: {
        std::vector<std::pair<std::string, const CBORValue*>> kv;
        kv.reserve(v.map.size());
        for (const auto& pr : v.map) {
            std::string key;
            cbor_encode(pr.first, key);
            kv.push_back({std::move(key), &pr.second});
        }
        std::sort(kv.begin(), kv.end(), [](const auto& a, const auto& b) {
            if (a.first.size() != b.first.size()) return a.first.size() < b.first.size();
            return a.first < b.first;
        });
        cbor_enc_head(out, 5, kv.size());
        for (const auto& pr : kv) {
            out += pr.first;
            cbor_encode(*pr.second, out);
        }
        break;
    }
    case CBORValue::T::Tag:
        cbor_enc_head(out, 6, v.tag);
        cbor_encode(v.tagvals[0], out);
        break;
    case CBORValue::T::Simple:
        if (v.is_null) {
            out.push_back(static_cast<char>(0xf6));
        } else if (v.is_bool) {
            out.push_back(v.boolv ? static_cast<char>(0xf5) : static_cast<char>(0xf4));
        }
        break;
    }
}

const CBORValue* cbor_map_get(const CBORValue& m, const std::string& key) {
    if (m.t != CBORValue::T::Map) return nullptr;
    for (const auto& pr : m.map) {
        if (pr.first.t == CBORValue::T::Text && pr.first.bytes == key) return &pr.second;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// CAR container: varint header length + DAG-CBOR header, then varint length +
// CID + data blocks. Byte-for-byte port of parse_car().
// ---------------------------------------------------------------------------

struct ParsedCar {
    CBORValue header;
    std::map<std::string, std::string> blocks;
};

bool parse_car(const std::string& data, ParsedCar& out, std::string& err) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());
    size_t n = data.size();
    size_t i = 0;
    uint64_t hlen = 0;
    if (!uvarint(p, n, i, hlen, err)) return false;
    if (hlen == 0 || i + hlen > n) {
        err = "truncated CAR header";
        return false;
    }
    CBORDecoder dec(p + i, static_cast<size_t>(hlen), err);
    if (!dec.decode(out.header)) return false;
    i += static_cast<size_t>(hlen);

    std::map<std::string, std::string> blocks;
    while (i < n) {
        uint64_t blen = 0;
        if (!uvarint(p, n, i, blen, err)) return false;
        size_t end = i + static_cast<size_t>(blen);
        if (end > n) {
            err = "block length exceeds CAR data";
            return false;
        }
        // CIDv1: 0x01 <codec varint> <mh code varint> <mh len varint> <digest>
        size_t start = i;
        if (i >= end || p[i] != 0x01) {
            err = "expected CIDv1";
            return false;
        }
        size_t j = i + 1;
        uint64_t codec = 0, mh = 0, dlen = 0;
        if (!uvarint(p, end, j, codec, err)) return false;
        if (!uvarint(p, end, j, mh, err)) return false;
        if (!uvarint(p, end, j, dlen, err)) return false;
        if (j + dlen > end) {
            err = "truncated CID";
            return false;
        }
        j += static_cast<size_t>(dlen);
        blocks[std::string(reinterpret_cast<const char*>(p + start), j - start)] =
            std::string(reinterpret_cast<const char*>(p + j), end - j);
        i = end;
    }
    out.blocks = std::move(blocks);
    return true;
}

// ---------------------------------------------------------------------------
// Minimal JSON parser for the DID document fetched from PLC.
// ---------------------------------------------------------------------------

struct Json {
    enum class T { Null, Bool, Num, Str, Arr, Obj };
    T t = T::Null;
    bool b = false;
    double num = 0;
    std::string s;
    std::vector<Json> arr;
    std::vector<std::pair<std::string, Json>> obj;

    const Json* get(const std::string& key) const {
        if (t != T::Obj) return nullptr;
        for (const auto& pr : obj) {
            if (pr.first == key) return &pr.second;
        }
        return nullptr;
    }
};

class JsonParser {
public:
    JsonParser(const std::string& s) : s_(s) {}

    bool parse(Json& out) {
        skip_ws();
        if (!value(out)) return false;
        skip_ws();
        return i_ == s_.size();
    }

    const std::string& error() const { return err_; }

private:
    const std::string& s_;
    size_t i_ = 0;
    std::string err_;

    bool fail() {
        if (err_.empty()) err_ = "invalid JSON";
        return false;
    }

    void skip_ws() {
        while (i_ < s_.size() &&
               (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r')) {
            i_++;
        }
    }

    static int hexval(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    static void append_utf8(std::string& s, unsigned cp) {
        if (cp < 0x80) {
            s.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            s.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            s.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            s.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            s.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    bool literal(Json& out, const char* word, Json::T t, bool bv) {
        size_t n = std::strlen(word);
        if (s_.compare(i_, n, word) != 0) return fail();
        i_ += n;
        out.t = t;
        out.b = bv;
        return true;
    }

    bool number(Json& out) {
        size_t start = i_;
        if (i_ < s_.size() && s_[i_] == '-') i_++;
        while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) i_++;
        if (i_ < s_.size() && s_[i_] == '.') {
            i_++;
            while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) i_++;
        }
        if (i_ < s_.size() && (s_[i_] == 'e' || s_[i_] == 'E')) {
            i_++;
            if (i_ < s_.size() && (s_[i_] == '+' || s_[i_] == '-')) i_++;
            while (i_ < s_.size() && std::isdigit(static_cast<unsigned char>(s_[i_]))) i_++;
        }
        if (i_ == start) return fail();
        std::string tok = s_.substr(start, i_ - start);
        try {
            out.num = std::stod(tok);
        } catch (...) {
            return fail();
        }
        out.t = Json::T::Num;
        return true;
    }

    bool string(Json& out) {
        if (i_ >= s_.size() || s_[i_] != '"') return fail();
        i_++;
        out.t = Json::T::Str;
        out.s.clear();
        while (true) {
            if (i_ >= s_.size()) return fail();
            char c = s_[i_++];
            if (c == '"') return true;
            if (c == '\\') {
                if (i_ >= s_.size()) return fail();
                char e = s_[i_++];
                switch (e) {
                case '"': out.s.push_back('"'); break;
                case '\\': out.s.push_back('\\'); break;
                case '/': out.s.push_back('/'); break;
                case 'b': out.s.push_back('\b'); break;
                case 'f': out.s.push_back('\f'); break;
                case 'n': out.s.push_back('\n'); break;
                case 'r': out.s.push_back('\r'); break;
                case 't': out.s.push_back('\t'); break;
                case 'u': {
                    unsigned cp = 0;
                    for (int k = 0; k < 4; k++) {
                        if (i_ >= s_.size()) return fail();
                        int d = hexval(s_[i_++]);
                        if (d < 0) return fail();
                        cp = (cp << 4) | static_cast<unsigned>(d);
                    }
                    if (cp >= 0xD800 && cp <= 0xDBFF) {
                        if (i_ + 2 <= s_.size() && s_[i_] == '\\' && s_[i_ + 1] == 'u') {
                            i_ += 2;
                            unsigned lo = 0;
                            for (int k = 0; k < 4; k++) {
                                if (i_ >= s_.size()) return fail();
                                int d = hexval(s_[i_++]);
                                if (d < 0) return fail();
                                lo = (lo << 4) | static_cast<unsigned>(d);
                            }
                            if (lo < 0xDC00 || lo > 0xDFFF) return fail();
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        } else {
                            return fail();
                        }
                    } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                        return fail();
                    }
                    append_utf8(out.s, cp);
                    break;
                }
                default: return fail();
                }
            } else {
                out.s.push_back(c);
            }
        }
    }

    bool array(Json& out) {
        i_++;
        out.t = Json::T::Arr;
        skip_ws();
        if (i_ < s_.size() && s_[i_] == ']') {
            i_++;
            return true;
        }
        while (true) {
            Json e;
            if (!value(e)) return false;
            out.arr.push_back(std::move(e));
            skip_ws();
            if (i_ >= s_.size()) return fail();
            char c = s_[i_++];
            if (c == ',') continue;
            if (c == ']') return true;
            return fail();
        }
    }

    bool object(Json& out) {
        i_++;
        out.t = Json::T::Obj;
        skip_ws();
        if (i_ < s_.size() && s_[i_] == '}') {
            i_++;
            return true;
        }
        while (true) {
            skip_ws();
            Json key;
            if (!string(key)) return false;
            skip_ws();
            if (i_ >= s_.size() || s_[i_] != ':') return fail();
            i_++;
            Json v;
            if (!value(v)) return false;
            out.obj.emplace_back(key.s, std::move(v));
            skip_ws();
            if (i_ >= s_.size()) return fail();
            char c = s_[i_++];
            if (c == ',') continue;
            if (c == '}') return true;
            return fail();
        }
    }

    bool value(Json& out) {
        skip_ws();
        if (i_ >= s_.size()) return fail();
        char c = s_[i_];
        switch (c) {
        case '{': return object(out);
        case '[': return array(out);
        case '"': return string(out);
        case 't': return literal(out, "true", Json::T::Bool, true);
        case 'f': return literal(out, "false", Json::T::Bool, false);
        case 'n': return literal(out, "null", Json::T::Null, false);
        default: return number(out);
        }
    }
};

// ---------------------------------------------------------------------------
// HTTPS fetch of the DID document (libcurl easy API).
// ---------------------------------------------------------------------------

size_t curl_write_cb(char* ptr, size_t size, size_t nmemb, void* userdata) {
    std::string* out = static_cast<std::string*>(userdata);
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

bool http_get(const std::string& url, std::string& body, std::string& err) {
    CURL* c = curl_easy_init();
    if (!c) {
        err = "curl init failed";
        return false;
    }
    char errbuf[CURL_ERROR_SIZE] = {0};
    body.clear();
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    curl_easy_setopt(c, CURLOPT_USERAGENT, "metalbear-verify/1.0");
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errbuf);
    CURLcode rc = curl_easy_perform(c);
    if (rc != CURLE_OK) {
        err = errbuf[0] ? errbuf : curl_easy_strerror(rc);
        curl_easy_cleanup(c);
        return false;
    }
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    curl_easy_cleanup(c);
    if (code < 200 || code >= 300) {
        err = "HTTP " + std::to_string(code);
        return false;
    }
    return true;
}

// Port of resolve_did_doc(): same URL construction for did:plc and did:web.
bool resolve_did_doc(const std::string& did, const std::string& plc_url, std::string& source,
                     Json& doc, std::string& err) {
    std::string url;
    if (did.rfind("did:plc:", 0) == 0) {
        url = plc_url + "/" + did;
    } else if (did.rfind("did:web:", 0) == 0) {
        std::string rest = did.substr(8);
        std::vector<std::string> parts;
        size_t start = 0;
        for (size_t pos = rest.find(':'); pos != std::string::npos; pos = rest.find(':', start)) {
            parts.push_back(rest.substr(start, pos - start));
            start = pos + 1;
        }
        parts.push_back(rest.substr(start));
        std::string host = parts[0];
        if (parts.size() > 1) {
            url = "https://" + host + "/";
            for (size_t k = 1; k < parts.size(); k++) {
                url += parts[k];
                if (k + 1 < parts.size()) url += "/";
            }
            url += "/did.json";
        } else {
            url = "https://" + host + "/.well-known/did.json";
        }
    } else {
        err = "unsupported DID method: " + did;
        return false;
    }
    std::string body;
    if (!http_get(url, body, err)) {
        err = "failed to fetch " + url + ": " + err;
        return false;
    }
    JsonParser jp(body);
    if (!jp.parse(doc)) {
        err = "invalid JSON from " + url;
        return false;
    }
    source = url;
    return true;
}

// ---------------------------------------------------------------------------
// secp256k1 verification. OpenSSL 3 uses the non-deprecated EVP_PKEY_fromdata
// path; older OpenSSL falls back to the EC_KEY API.
// ---------------------------------------------------------------------------

#if OPENSSL_VERSION_NUMBER >= 0x30000000L

EVP_PKEY* load_secp256k1_pub(const uint8_t* pt, size_t len) {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* cctx = nullptr;
    OSSL_PARAM_BLD* bld = nullptr;
    OSSL_PARAM* params = nullptr;
    cctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    bld = OSSL_PARAM_BLD_new();
    if (!cctx || !bld) goto out;
    if (EVP_PKEY_fromdata_init(cctx) <= 0) goto out;
    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "secp256k1", 0) != 1)
        goto out;
    if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, pt, len) != 1) goto out;
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto out;
    if (EVP_PKEY_fromdata(cctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) pkey = nullptr;
out:
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_CTX_free(cctx);
    return pkey;
}

#else  // OpenSSL < 3.0

EVP_PKEY* load_secp256k1_pub(const uint8_t* pt, size_t len) {
    EC_KEY* ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return nullptr;
    const uint8_t* q = pt;
    if (o2i_ECPublicKey(&ec, &q, static_cast<long>(len)) == nullptr) {
        EC_KEY_free(ec);
        return nullptr;
    }
    EVP_PKEY* pkey = EVP_PKEY_new();
    if (!pkey) {
        EC_KEY_free(ec);
        return nullptr;
    }
    if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EVP_PKEY_free(pkey);
        return nullptr;
    }
    return pkey;
}

#endif

std::string der_len(size_t n) {
    if (n < 0x80) return std::string(1, static_cast<char>(n));
    std::string b;
    size_t x = n;
    while (x) {
        b.insert(b.begin(), static_cast<char>(x & 0xff));
        x >>= 8;
    }
    return std::string(1, static_cast<char>(0x80 | b.size())) + b;
}

// DER INTEGER of a big-endian value, matching cryptography's
// encode_dss_signature() semantics.
std::string der_integer(const uint8_t* v, size_t n) {
    size_t s = 0;
    while (s < n && v[s] == 0) s++;
    std::string body;
    if (s == n) {
        body.push_back('\0');
    } else {
        if (v[s] & 0x80) body.push_back('\0');
        body.append(reinterpret_cast<const char*>(v + s), n - s);
    }
    return std::string("\x02", 1) + der_len(body.size()) + body;
}

// 64-byte compact r||s -> DER SEQUENCE { INTEGER r, INTEGER s }.
std::string der_ecdsa(const uint8_t sig[64]) {
    std::string content = der_integer(sig, 32) + der_integer(sig + 32, 32);
    return std::string("\x30", 1) + der_len(content.size()) + content;
}

bool verify_signature(EVP_PKEY* pkey, const std::string& data, const uint8_t sig[64]) {
    std::string der = der_ecdsa(sig);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) == 1 &&
        EVP_DigestUpdate(ctx, data.data(), data.size()) == 1) {
        ok = EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(der.data()),
                                   der.size()) == 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool sha256(const std::string& in, uint8_t out[32]) {
    unsigned int len = 0;
    return EVP_Digest(reinterpret_cast<const unsigned char*>(in.data()), in.size(), out, &len,
                      EVP_sha256(), nullptr) == 1 &&
           len == 32;
}

// ---------------------------------------------------------------------------
// Helpers and the main verification flow.
// ---------------------------------------------------------------------------

int fail(const std::string& msg) {
    std::cerr << "error: " << msg << "\n";
    return 1;
}

void usage() {
    std::cerr << "Usage: verify_repo_car <car_path> <did>\n";
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return 1;
    }
    std::string car_path = argv[1];
    std::string did = argv[2];

    std::ifstream f(car_path, std::ios::binary);
    if (!f) {
        std::cerr << "error: cannot open " << car_path << "\n";
        return 1;
    }
    std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (data.empty()) {
        std::cerr << "error: empty CAR file\n";
        return 1;
    }

    std::string err;
    ParsedCar car;
    if (!parse_car(data, car, err)) return fail(err);

    const CBORValue* roots = cbor_map_get(car.header, "roots");
    if (!roots || roots->t != CBORValue::T::Array) return fail("CAR header has no 'roots'");
    if (roots->array.empty()) return fail("CAR has no root commits");
    const CBORValue& root = roots->array[0];

    // cbor2 surfaces CID links as tag 42 whose value is the raw multibase
    // identity form: a leading 0x00 followed by the binary CID.
    std::string root_bytes;
    if (root.t == CBORValue::T::Tag) {
        if (root.tagvals.empty() || root.tagvals[0].t != CBORValue::T::Bytes) return fail("invalid root CID encoding");
        root_bytes = root.tagvals[0].bytes;
    } else if (root.t == CBORValue::T::Bytes) {
        root_bytes = root.bytes;
    } else {
        return fail("invalid root CID encoding");
    }
    if (!root_bytes.empty() && static_cast<unsigned char>(root_bytes[0]) == 0x00) {
        root_bytes.erase(0, 1);
    }

    std::cout << "CAR roots: " << roots->array.size() << " blocks: " << car.blocks.size() << "\n";
    std::cout << "root commit CID: " << "b" + base32_lower_nopad(root_bytes) << "\n";

    auto block_it = car.blocks.find(root_bytes);
    if (block_it == car.blocks.end()) return fail("root commit block not present in CAR");

    // The root's CID must actually be the hash of its block (content addressing).
    uint8_t digest[32];
    if (!sha256(block_it->second, digest)) return fail("sha256 failed");
    if (root_bytes.size() < 32 ||
        std::memcmp(root_bytes.data() + root_bytes.size() - 32, digest, 32) != 0)
        return fail("root CID does not match block hash");
    std::cout << "root CID matches block digest: OK\n";

    CBORDecoder dec(reinterpret_cast<const uint8_t*>(block_it->second.data()),
                    block_it->second.size(), err);
    CBORValue commit;
    if (!dec.decode(commit)) return fail(err);
    if (commit.t != CBORValue::T::Map) return fail("commit block is not a map");

    const CBORValue* didv = cbor_map_get(commit, "did");
    if (!didv) return fail("key error: 'did'");
    const CBORValue* version = cbor_map_get(commit, "version");
    if (!version) return fail("key error: 'version'");
    const CBORValue* rev = cbor_map_get(commit, "rev");
    if (!rev) return fail("key error: 'rev'");
    if (didv->t != CBORValue::T::Text) return fail("commit 'did' is not a string");
    if (version->t != CBORValue::T::Int) return fail("commit 'version' is not an integer");
    if (rev->t != CBORValue::T::Text) return fail("commit 'rev' is not a string");
    const std::string commit_did = didv->bytes;
    const int64_t commit_version = version->i;
    const std::string commit_rev = rev->bytes;

    std::cout << "commit did: " << commit_did << " version: " << commit_version
              << " rev: " << commit_rev << "\n";

    if (commit_did != did) return fail("commit claims " + commit_did + ", expected " + did);

    std::string sig;
    {
        auto sig_it = commit.map.end();
        for (auto it = commit.map.begin(); it != commit.map.end(); ++it) {
            if (it->first.t == CBORValue::T::Text && it->first.bytes == "sig") {
                sig_it = it;
                break;
            }
        }
        if (sig_it == commit.map.end()) return fail("key error: 'sig'");
        if (sig_it->second.t != CBORValue::T::Bytes) return fail("commit 'sig' is not a byte string");
        sig = sig_it->second.bytes;
        commit.map.erase(sig_it);
    }
    std::string unsigned_cbor;
    cbor_encode(commit, unsigned_cbor);

    std::string source;
    Json doc;
    if (!resolve_did_doc(did, kPlcUrl, source, doc, err)) return fail(err);

    const Json* vms = doc.get("verificationMethod");
    if (!vms || vms->t != Json::T::Arr) return fail("key error: 'verificationMethod'");
    const Json* vm = nullptr;
    for (const auto& m : vms->arr) {
        const Json* id = m.get("id");
        if (id && id->t == Json::T::Str && id->s.size() >= 8 &&
            id->s.compare(id->s.size() - 8, 8, "#atproto") == 0) {
            vm = &m;
            break;
        }
    }
    if (!vm) return fail("no verification method with id ending #atproto");
    const Json* mbj = vm->get("publicKeyMultibase");
    if (!mbj || mbj->t != Json::T::Str) return fail("key error: 'publicKeyMultibase'");
    const std::string mb = mbj->s;
    if (mb.empty() || mb[0] != 'z') return fail("publicKeyMultibase must start with 'z'");
    const std::string raw = b58decode(mb.substr(1), err);
    if (!err.empty()) return fail(err);
    if (raw.size() < 2 || static_cast<unsigned char>(raw[0]) != 0xe7 ||
        static_cast<unsigned char>(raw[1]) != 0x01) {
        std::ostringstream hx;
        size_t n = std::min<size_t>(2, raw.size());
        for (size_t k = 0; k < n; k++) {
            char b[3];
            std::snprintf(b, sizeof(b), "%02x", static_cast<unsigned char>(raw[k]));
            hx << b;
        }
        return fail("expected secp256k1-pub multicodec, got " + hx.str());
    }
    const std::string pub_compressed = raw.substr(2);
    if (pub_compressed.size() != 33 ||
        (static_cast<unsigned char>(pub_compressed[0]) != 0x02 &&
         static_cast<unsigned char>(pub_compressed[0]) != 0x03))
        return fail("invalid public key encoding");

    std::cout << "published signing key: " << mb << " (from " << source << ")\n";

    if (sig.size() != 64) {
        std::cout << "COMMIT SIGNATURE: INVALID - a relay would reject this repo\n";
        return 1;
    }
    EVP_PKEY* pkey = load_secp256k1_pub(reinterpret_cast<const uint8_t*>(pub_compressed.data()),
                                        pub_compressed.size());
    if (!pkey) return fail("failed to build public key");
    const bool valid = verify_signature(pkey, unsigned_cbor,
                                        reinterpret_cast<const uint8_t*>(sig.data()));
    EVP_PKEY_free(pkey);
    if (!valid) {
        std::cout << "COMMIT SIGNATURE: INVALID - a relay would reject this repo\n";
        return 1;
    }
    std::cout << "COMMIT SIGNATURE: VALID against the published key\n";
    return 0;
}
