"""Independently verify a MetalBear repo CAR against the key published in PLC.

Uses neither MetalBear nor Wolfram: CAR framing, DAG-CBOR re-encoding, and
secp256k1 verification are all done here, so a pass means a third party (relay,
AppView) would accept the repo.
"""
import sys, json, hashlib, urllib.request
import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58decode(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw

def uvarint(buf, i):
    x = 0; shift = 0
    while True:
        b = buf[i]; i += 1
        x |= (b & 0x7F) << shift
        if not (b & 0x80): return x, i
        shift += 7

def parse_car(data):
    hlen, i = uvarint(data, 0)
    header = cbor2.loads(data[i:i+hlen]); i += hlen
    blocks = {}
    while i < len(data):
        blen, i = uvarint(data, i)
        end = i + blen
        # CIDv1: 0x01 <codec varint> <mh code varint> <mh len varint> <digest>
        start = i
        assert data[i] == 0x01, "expected CIDv1"
        j = i + 1
        _codec, j = uvarint(data, j)
        _mh, j = uvarint(data, j)
        dlen, j = uvarint(data, j)
        j += dlen
        cid = data[start:j]
        blocks[cid] = data[j:end]
        i = end
    return header, blocks

def cid_str(cid: bytes) -> str:
    # base32 lower, no padding, 'b' multibase prefix
    import base64
    return "b" + base64.b32encode(cid).decode().lower().rstrip("=")

def dag_cbor_encode(obj):
    return cbor2.dumps(obj, canonical=True, default=_default)

def _default(encoder, value):
    raise TypeError(f"unexpected {type(value)}")

def main(car_path, did, plc_url="https://plc.directory"):
    data = open(car_path, "rb").read()
    header, blocks = parse_car(data)
    roots = header["roots"]
    root = roots[0]
    # cbor2 surfaces CID links as tag 42 whose value is the raw multibase
    # identity form: a leading 0x00 followed by the binary CID.
    root_bytes = root.value if isinstance(root, cbor2.CBORTag) else bytes(root)
    if root_bytes[:1] == b"\x00":
        root_bytes = root_bytes[1:]
    print("CAR roots:", len(roots), "blocks:", len(blocks))
    print("root commit CID:", cid_str(root_bytes))

    commit_cbor = blocks.get(root_bytes)
    assert commit_cbor is not None, "root commit block not present in CAR"

    # The root's CID must actually be the hash of its block (content addressing).
    digest = hashlib.sha256(commit_cbor).digest()
    assert root_bytes.endswith(digest), "root CID does not match block hash"
    print("root CID matches block digest: OK")

    commit = cbor2.loads(commit_cbor)
    print("commit did:", commit["did"], "version:", commit["version"], "rev:", commit["rev"])
    assert commit["did"] == did, f"commit claims {commit['did']}, expected {did}"

    sig = commit.pop("sig")
    unsigned = dag_cbor_encode(commit)

    doc = json.load(urllib.request.urlopen(f"{plc_url}/{did}", timeout=20))
    vm = [m for m in doc["verificationMethod"] if m["id"].endswith("#atproto")][0]
    mb = vm["publicKeyMultibase"]
    assert mb[0] == "z"
    raw = b58decode(mb[1:])
    assert raw[:2] == b"\xe7\x01", f"expected secp256k1-pub multicodec, got {raw[:2].hex()}"
    pub_compressed = raw[2:]
    print("PLC signing key:", mb)

    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), pub_compressed)
    r = int.from_bytes(sig[:32], "big"); s = int.from_bytes(sig[32:], "big")
    der = asym_utils.encode_dss_signature(r, s)
    try:
        pub.verify(der, unsigned, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        print("COMMIT SIGNATURE: INVALID — a relay would reject this repo")
        return 1
    print("COMMIT SIGNATURE: VALID against the PLC-published key")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2]))
