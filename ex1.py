import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import base64

BEGIN_RSA_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----"
END_RSA_PRIVATE_KEY = "-----END RSA PRIVATE KEY-----"
BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----"
END_PUBLIC_KEY = "-----END PUBLIC KEY-----"
MAX_PEM_LINES = 1000
CMD_INSERT = '1'
CMD_ROOT = '2'
CMD_PROOF = '3'
CMD_VERIFY = '4'
CMD_GEN_KEYS = '5'
CMD_SIGN = '6'
CMD_CHECK_SIG = '7'

def H(x):
    return hashlib.sha256(x).digest()

def gen():
    sk = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    sk_pem = sk.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    pk = sk.public_key()
    pk_pem = pk.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return sk_pem.decode(), pk_pem.decode()

def get_pem_key(begin_marker, end_marker, max_lines=MAX_PEM_LINES):
    lines = [begin_marker]
    for _ in range(max_lines):
        try:
            line = input().rstrip()
        except EOFError:
            break
        lines.append(line)
        if line == end_marker:
            return "\n".join(lines)
    return None

def verify_signature(pk_pem_str, sig, data_str):
    try:
        pk = serialization.load_pem_public_key(
            pk_pem_str.encode(),
            backend=default_backend()
        )
        pk.verify(
            sig,
            bytes.fromhex(data_str),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        return False

class MerkelTree:
    def __init__(self):
        self.leaves = []
        self.root_hash = b''

    def insert(self, data):
        self.leaves.append(data.encode())
        self.root_hash = self._root_range(0, len(self.leaves))

    def get_root(self):
        return self.root_hash

    def get_leafs_cnt(self):
        return len(self.leaves)

    def _root_range(self, l, h):
        length = h - l
        if length == 1:
            return H(self.leaves[l])
        split_index = 1 << ((length - 1).bit_length() - 1)
        m = l + split_index
        left_hash = self._root_range(l, m)
        right_hash = self._root_range(m, h)
        return H((left_hash.hex() + right_hash.hex()).encode())

    def get_proof(self, index, l, h):
        length = h - l
        if length == 1:
            return []
        split_index = 1 << ((length - 1).bit_length() - 1)
        m = l + split_index
        if index < m:
            proof = self.get_proof(index, l, m)
            sib = self._root_range(m, h)
            proof.append('1' + sib.hex())
        else:
            proof = self.get_proof(index, m, h)
            sib = self._root_range(l, m)
            proof.append('0' + sib.hex())
        return proof

    @staticmethod
    def verify(data, proof, root_bytes):
        try:
            h = H(data.encode())
            for item in proof:
                bit = item[0]
                sib = bytes.fromhex(item[1:])
                concat_hex = (sib.hex() + h.hex()) if bit == '0' else (h.hex() + sib.hex())
                h = H(concat_hex.encode())
            return h == root_bytes
        except Exception as e:
            return False

    def sign(self, sk_pem):
        try:
            sk = serialization.load_pem_private_key(
                sk_pem.encode(),
                password=None,
                backend=default_backend()
            )
            return sk.sign(
                self.get_root(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
        except Exception as e:
            return False

def validate_cmd(parts, tree):
    if not parts:
        return False
    cmd = parts[0]
    if cmd == CMD_INSERT:
        return len(parts) == 2
    if cmd == CMD_ROOT:
        return len(parts) == 1
    if cmd == CMD_PROOF:
        if len(parts) != 2 or not parts[1].isdigit():
            return False
        idx = int(parts[1])
        return 0 <= idx < tree.get_leafs_cnt()
    if cmd == CMD_VERIFY:
        if len(parts) < 3:
            return False
        return True
    if cmd == CMD_GEN_KEYS:
        return len(parts) == 1
    if cmd == CMD_SIGN:
        return ' '.join(parts[1:]) == BEGIN_RSA_PRIVATE_KEY
    if cmd == CMD_CHECK_SIG:
        return ' '.join(parts[1:]) == BEGIN_PUBLIC_KEY
    return False

def main():
    tree = MerkelTree()
    try:
        while True:
            line = input().strip()
            if not line:
                continue
            parts = line.split()
            if not validate_cmd(parts, tree):
                print()
                continue

            cmd = parts[0]
            if cmd == CMD_INSERT:
                tree.insert(parts[1])

            elif cmd == CMD_ROOT:
                print(tree.get_root().hex())

            elif cmd == CMD_PROOF:
                idx = int(parts[1])
                root_hex = tree.get_root().hex()
                proof = tree.get_proof(idx, 0, tree.get_leafs_cnt())
                print(root_hex, *proof)

            elif cmd == CMD_VERIFY:
                data = parts[1]
                try:
                    root_bytes = bytes.fromhex(parts[2])
                except ValueError:
                    print(False)
                    continue
                proof_items = parts[3:]
                print(MerkelTree.verify(data, proof_items, root_bytes))
                
            elif cmd == CMD_GEN_KEYS:
                sk_pem, pk_pem = gen()
                print(sk_pem)
                print(pk_pem)

            elif cmd == CMD_SIGN:
                sk_pem = get_pem_key(BEGIN_RSA_PRIVATE_KEY, END_RSA_PRIVATE_KEY)
                if not sk_pem:
                    print()
                    continue
                _ = input()  # skip blank line
                print(base64.b64encode(tree.sign(sk_pem)).decode())

            elif cmd == CMD_CHECK_SIG:
                pk_pem = get_pem_key(BEGIN_PUBLIC_KEY, END_PUBLIC_KEY)
                if not pk_pem:
                    print()
                    continue
                _ = input()  # skip blank line
                sig_data = input().rstrip().split()
                if len(sig_data) != 2:
                    print()
                    continue
                sig_b64, data_str = sig_data
                try:
                    sig_bytes = base64.b64decode(sig_b64)
                except (ValueError, base64.binascii.Error):
                    print(False)
                    continue
                print(verify_signature(pk_pem, sig_bytes, data_str))
            else:
                print()
    except EOFError:
        pass

if __name__ == '__main__':
    main()
