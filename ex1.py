import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Constants
RSA_PRIVATE_KEY = "RSA PRIVATE KEY"
RSA_PUBLIC_KEY = "PUBLIC KEY"
BEGIN_PRIVATE_KEY = f"-----BEGIN {RSA_PRIVATE_KEY}-----"
END_PRIVATE_KEY = f"-----END {RSA_PRIVATE_KEY}-----"
BEGIN_PUBLIC_KEY = f"-----BEGIN {RSA_PUBLIC_KEY}-----"
END_PUBLIC_KEY = f"-----END {RSA_PUBLIC_KEY}-----"
CMD_INSERT = "1"
CMD_GET_ROOT = "2"
CMD_GET_PROOF = "3"
CMD_VERIFY = "4"
CMD_GENERATE_KEYS = "5"
CMD_SIGN = "6"
CMD_VERIFY_SIGNATURE = "7"
MAX_PEM_LINES = 1000

# Cryptographic functions
def H(x):
    return hashlib.sha256(x).digest()

def gen():
    # Generate a new RSA key pair
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

def verify_signature(pk_pem_str, sig_hex, data):
    try:
        pk = serialization.load_pem_public_key(
            pk_pem_str.encode(),
            backend=default_backend()
        )
        sig = bytes.fromhex(sig_hex)
        try:
            pk.verify(
                sig,
                bytes.fromhex(data),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    except (ValueError, TypeError):
        return False

# Input/Output functions
def read_pem_key(key_type, max_lines=MAX_PEM_LINES):
    """Safely read a PEM key from input with line limit protection."""
    pem_lines = []
    end_marker = f"END {key_type}"
    line_count = 0
    
    try:
        while line_count < max_lines:
            line = input().rstrip()
            pem_lines.append(line)
            line_count += 1
            if end_marker in line and input() == "":
                return "\n".join(pem_lines) + "\n"
        # If we reach here, we've hit the max line limit without finding the end marker
        return None
    except Exception:
        return None

class MerkleTree:
    def __init__(self):
        self.leaves = []
        self.root_hash = b''

    def insert(self, data):
        # store string as bytes
        self.leaves.append(data.encode())
        self.root_hash = self._root_range(0, len(self.leaves))
        
    def get_root(self):
        return self.root_hash
        
    def get_leafs_cnt(self):
        return len(self.leaves)

    def _root_range(self, l, h):
        length = h - l
        # base case: single leaf
        if length == 1:
            return H(self.leaves[l])
        # determine split point (largest power of two < length)
        split_index = 1 << ((length - 1).bit_length() - 1)
        m = l + split_index
        left_hash = self._root_range(l, m)
        right_hash = self._root_range(m, h)
        return H((left_hash.hex() + right_hash.hex()).encode())

    def get_proof(self, index, l, h):
        length = h - l
        # base case: reached the leaf
        if length == 1:
            return []
        split_index = 1 << ((length - 1).bit_length() - 1)
        m = l + split_index
        if index < m:
            # leaf in left subtree: get proof then append right sibling
            proof = self.get_proof(index, l, m)
            sib = self._root_range(m, h)
            proof.append('1' + sib.hex())
        else:
            # leaf in right subtree: adjust index and append left sibling
            proof = self.get_proof(index, m, h)
            sib = self._root_range(l, m)
            proof.append('0' + sib.hex())
        return proof

    @staticmethod
    def verify(data, proof, root_bytes):
        try:
            # recompute hash from leaf up
            h = H(data.encode())
            for i, item in enumerate(proof):
                if not item or item[0] not in ('0', '1'):
                    return False
                try:
                    bit = item[0]
                    sib = bytes.fromhex(item[1:])
                    if bit == '0':
                        concat_hex = sib.hex() + h.hex()
                    else:
                        concat_hex = h.hex() + sib.hex()
                    h = H(concat_hex.encode())
                except (ValueError, IndexError) as e:
                    return False
            result = h == root_bytes
            return result
        except Exception as e:
            return False

    def sign(self, sk_pem):
        try:
            sk = serialization.load_pem_private_key(
                sk_pem.encode(),
                password=None,
                backend=default_backend()
            )
            sig = sk.sign(
                self.get_root(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return sig
        except Exception:
            return None

# Command handlers
def handle_insert(tree, parts):
    if len(parts) != 2:
        return
    data = parts[1]
    tree.insert(data)
    return

def handle_get_root(tree):
    if tree.get_leafs_cnt() == 0:
        return ""
    return tree.get_root().hex()

def handle_get_proof(tree, parts):
    if len(parts) != 2:
        return ""
    
    try:
        idx = int(parts[1])
        if idx < 0 or idx >= tree.get_leafs_cnt():
            return ""
        
        root_hex = tree.get_root().hex()
        proof = tree.get_proof(idx, 0, len(tree.leaves))
        return root_hex + ' ' + ' '.join(proof)
    except ValueError as e:
        return ""

def handle_verify(parts):
    if len(parts) < 4:
        return ""
    
    data = parts[1]
    root_hex = parts[2]
    proof_items = parts[3:]
    
    try:
        root_bytes = bytes.fromhex(root_hex)
        valid = MerkleTree.verify(data, proof_items, root_bytes)
        return str(valid).capitalize()  # Output True/False with capital letter
    except ValueError as e:
        return "False"

def handle_generate_keys():
    sk_pem, pk_pem = gen()
    return f"{sk_pem}\n{pk_pem}"

def handle_sign(tree, parts):
    if len(parts) < 2 or " ".join(parts[1:]) != BEGIN_PRIVATE_KEY.strip():
        return ""
        
    sk_pem = read_pem_key(RSA_PRIVATE_KEY)
    if not sk_pem:
        return ""
        
    sk_pem = f"{BEGIN_PRIVATE_KEY}\n{sk_pem}"
    
    signature = tree.sign(sk_pem)
    return signature.hex() if signature else ""

def handle_verify_signature(parts):
    if len(parts) < 2 or " ".join(parts[1:]) != BEGIN_PUBLIC_KEY.strip():
        return ""
        
    pk_pem = read_pem_key(RSA_PUBLIC_KEY)
    if not pk_pem:
        return ""
        
    pk_pem = f"{BEGIN_PUBLIC_KEY}\n{pk_pem}"
    
    try:
        # read the signature and the data safely
        sig_data_line = input().rstrip()
        sig_data = sig_data_line.split()
        
        if len(sig_data) < 2:
            return "False"
            
        sig = sig_data[0]
        data = sig_data[1]
        
        # verify the signature
        result = verify_signature(pk_pem, sig, data)
        return str(result).capitalize()
    except Exception:
        return "False"

def main():
    tree = MerkleTree()
    try:
        while True:
            try:
                line = input().strip()
                if not line:
                    print()
                    continue
                
                parts = line.split()
                if not parts:
                    print()
                    continue
                    
                cmd = parts[0]
                result = ""
                
                if cmd == CMD_INSERT:
                    handle_insert(tree, parts)
                
                elif cmd == CMD_GET_ROOT:
                    result = handle_get_root(tree)
                    print(result)
                
                elif cmd == CMD_GET_PROOF:
                    result = handle_get_proof(tree, parts)
                    print(result)
                
                elif cmd == CMD_VERIFY:
                    result = handle_verify(parts)
                    print(result)
                
                elif cmd == CMD_GENERATE_KEYS:
                    result = handle_generate_keys()
                    print(result)
                
                elif cmd == CMD_SIGN:
                    result = handle_sign(tree, parts)
                    print(result)
                
                elif cmd == CMD_VERIFY_SIGNATURE:
                    result = handle_verify_signature(parts)
                    print(result)
                
                else:
                    print()
            except Exception:
                print()
                continue
    except Exception:
        pass

if __name__ == '__main__':
    main()
