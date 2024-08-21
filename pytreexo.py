import copy
import hashlib


class Proof:
    def __init__(self, targets: [int], proof: [bytes]):
        self.targets = targets
        self.proof = proof

    def __str__(self):
        proof_str = [x.hex() for x in self.proof]
        s = "targets {}, proof {}".format(self.targets, proof_str)
        return s

    def __copy__(self):
        return Proof(self.targets.copy(), self.proof.copy())


class Stump:
    def __init__(self):
        self.numleaves = 0
        self.roots = []

    def __str__(self):
        roots_str = [x.hex() if x is not None else "None" for x in self.roots]
        s = "numleaves {}, roots {}".format(self.numleaves, roots_str)
        return s

    def __eq__(self, other):
        return self.roots == other.roots and self.numleaves == other.numleaves

    def add(self, adds: [bytes]):
        for add in adds:
            for row in range(tree_rows(self.numleaves)+1):
                if (self.numleaves >> row) & 1 == 0:
                    break
                root = self.roots.pop()
                add = parent_hash(root, add)

            self.roots.append(add)
            self.numleaves += 1

    def verify(self, dels: [bytes], proof: Proof) -> [int]:
        if len(dels) != len(proof.targets):
            raise("len of dels and proof.targets differ")

        root_candidates = calculate_roots(self.numleaves, dels, proof)

        root_idxs = []
        for i in range(len(self.roots)):
            j = len(self.roots) - (i+1)
            if len(root_candidates) > len(root_idxs):
                if self.roots[j] == root_candidates[len(root_idxs)]:
                    root_idxs.append(j)

        if len(root_idxs) != len(root_candidates):
            raise("calculated roots from the proof and matched roots differ")

        return root_idxs

    def delete(self, dels: [bytes], proof: Proof):
        dels_copy = dels.copy()
        proof_copy = copy.copy(proof)
        root_idxs = self.verify(dels_copy, proof_copy)

        modified_roots = calculate_roots(self.numleaves, None, proof)

        for i, idx in enumerate(root_idxs):
            self.roots[idx] = modified_roots[i]


def parent_hash(left, right):
    if left is None: return right
    if right is None: return left
    return hashlib.new('sha512_256', left+right).digest()


def parent(pos: int, total_rows: int) -> int:
    return (pos >> 1) | (1 << total_rows)


def tree_rows(n: int) -> int:
    return 0 if n == 0 else (n - 1).bit_length()


def row_maxpos(row: int, total_row: int) -> int:
    mask = (2 << total_row) - 1
    return ((mask << int(total_row-row)) & mask) - 1


def root_position(leaves: int, row: int, total_rows: int) -> int:
    mask = (2 << total_rows) - 1
    before = leaves & (mask << (row + 1))
    shifted = (before >> row) | (mask << (total_rows + 1 - row))
    return shifted & mask


def isroot(position: int, numleaves: int, row: int, total_rows: int) -> bool:
    root_present = numleaves & (1 << row) != 0
    rootpos = root_position(numleaves, row, total_rows)
    return root_present and rootpos == position


def next_least_list(list0, list1):
    if list0 and list1:
        if list0[0] < list1[0]:
            return 0
        else:
            return 1
    elif list0 and not list1:
        return 0
    elif not list0 and list1:
        return 1
    else:
        return None


def calculate_roots(numleaves: int, dels: [bytes], proof: Proof) -> [bytes]:
    total_rows = tree_rows(numleaves)

    if not proof.targets:
        return []

    dels = dels if dels is not None else [None] * len(proof.targets)
    proof.targets, dels = (list(t) for t in zip(*sorted(zip(proof.targets, dels))))

    next_hashes, next_positions, calculated_roots = [], [], []

    row = 0
    while row <= total_rows:
        pos, cur_hash = -1, bytes
        sib_present, sib_pos, sib_hash = False, -1, bytes

        index = next_least_list(proof.targets, next_positions)
        if index is None:
            break

        pos = proof.targets.pop(0) if index == 0 else next_positions.pop(0)
        cur_hash = dels.pop(0) if index == 0 else next_hashes.pop(0)

        while pos > row_maxpos(row, total_rows):
            row += 1

        if isroot(pos, numleaves, row, total_rows):
            calculated_roots.append(cur_hash)
            continue

        index = next_least_list(proof.targets, next_positions)
        if index is not None:
            sib_pos = proof.targets[0] if index == 0 else next_positions[0]
            if pos | 1 == sib_pos:
                sib_present = True
                sib_pos = proof.targets.pop(0) if index == 0 else next_positions.pop(0)
                sib_hash = dels.pop(0) if index == 0 else next_hashes.pop(0)

        next_hash = bytes
        if sib_present:
            next_hash = parent_hash(cur_hash, sib_hash)
        else:
            proofhash = proof.proof.pop(0)

            if pos & 1 == 0:
                next_hash = parent_hash(cur_hash, proofhash)
            else:
                next_hash = parent_hash(proofhash, cur_hash)

        next_hashes.append(next_hash)
        next_positions.append(parent(pos, total_rows))

    return calculated_roots
