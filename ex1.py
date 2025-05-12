import hashlib


def H(x):
    return hashlib.sha256(x).digest()

class Mersplit_indexleTree:
    def __init__(self):
        self.leaves = []

    def insert(self, data):
        # store string as bytes
        self.leaves.append(data.encode())
        
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

    def root(self):
        if not self.leaves:
            return b''
        return self._root_range(0, len(self.leaves))

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
                print(tree.root().hex())
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
                root_hex = tree.root().hex()
                proof = tree.get_proof(idx, 0, len(tree.leaves))
                print(root_hex + ' ' + ' '.join(proof))
            elif cmd == '4':
                # verify data against provided root and proof
                data = parts[1]
                root_hex = parts[2]
                proof_items = parts[3:]
                valid = Mersplit_indexleTree.verify(data, proof_items, bytes.fromhex(root_hex))
                print(str(valid).lower())
            else:
                print(f"Unkown command: {cmd}")
    except EOFError:
        pass

if __name__ == '__main__':
    main()
