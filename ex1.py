import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

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

class Mersplit_indexleTree:
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
            proof = self.get_proof(index - split_index, m, h)
            sib = self._root_range(l, m)
            proof.append('0' + sib.hex())
        return proof

    @staticmethod
    def verify(data, proof, root_bytes):
        # recompute hash from leaf up
        h = H(data.encode())
        for item in proof:
            bit = item[0]
            sib = bytes.fromhex(item[1:])
            if bit == '0':
                concat_hex = sib.hex() + h.hex()
            else:
                concat_hex = h.hex() + sib.hex()
            h = H(concat_hex.encode())
        return h == root_bytes

    def sign(self, sk_pem):
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
    
def main():
    tree = Mersplit_indexleTree()
    try:
        while True:
            line = input().strip()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0]
            if cmd == '1':
                # validate input - needs to be "1 <leaf>"
                if len(parts) != 2:
                    print()
                    continue
                # insert leaf
                data = parts[1]
                tree.insert(data)
            elif cmd == '2':
                # check input is valid
                if len(parts) != 1:
                    print()
                    continue
                # print root hash
                print(tree.get_root().hex())
            elif cmd == '3':
                # check input is valid
                if len(parts) != 2:
                    print()
                    continue
                # print root and proof
                idx = int(parts[1])
                if idx < 0 or idx >= tree.get_leafs_cnt():
                    print()
                    continue
                root_hex = tree.get_root().hex()
                proof = tree.get_proof(idx, 0, len(tree.leaves))
                print(root_hex + ' ' + ' '.join(proof))
            elif cmd == '4':
                # validate input - needs to be "4 <data> <root> <proof>"
                if len(parts) < 4:
                    print()
                    continue
                # verify data against provided root and proof
                data = parts[1]
                root_hex = parts[2]
                proof_items = parts[3:]
                valid = Mersplit_indexleTree.verify(data, proof_items, bytes.fromhex(root_hex))
                print(str(valid))
            elif cmd == '5':
                # validate input
                if len(parts) != 1:
                    print()
                    continue
                sk_pem, pk_pem = gen()
                print(sk_pem)
                print(pk_pem)
            elif cmd == '6':
                # can we assume that the pem key is valid and wont contain a infinite loop?
                # validate input
                pem_lines = []
                while True:
                    l = input().rstrip()
                    pem_lines.append(l)
                    if 'END RSA PRIVATE KEY' in l:
                        break
                sk_pem = "\n".join(pem_lines) + "\n"
                sk_pem = "-----BEGIN RSA PRIVATE KEY-----\n" + sk_pem
                print(tree.sign(sk_pem).hex())
                
            elif cmd == '7':
                # need to check if the infinte loop like before
                # read input in format: 7 <pem> <sig> <data> and call the verifier
                pem_lines = []
                while True:
                    l = input().rstrip()
                    pem_lines.append(l)
                    if 'END PUBLIC KEY' in l:
                        break
                pk_pem = "\n".join(pem_lines) + "\n"
                pk_pem = "-----BEGIN PUBLIC KEY-----\n" + pk_pem
                # read the addional new line from the pem
                input()
                # read the signature and the data(they are in the same line separated by space)
                sig_data = input().rstrip().split()
                sig = sig_data[0]
                data = sig_data[1]
                # verify the signature
                print(verify_signature(pk_pem, sig, data))
            
            else:
                print(f"[DEBUG] Unkown command: {cmd}")
    except EOFError:
        pass

if __name__ == '__main__':
    main()
