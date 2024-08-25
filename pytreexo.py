import bisect
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

    def add(self, add: bytes):
        for row in range(tree_rows(self.numleaves)+1):
            if not root_present(self.numleaves, row): break
            root = self.roots.pop()
            add = parent_hash(root, add)

        self.roots.append(add)
        self.numleaves += 1

    def verify(self, dels: [bytes], proof: Proof):
        if len(dels) != len(proof.targets):
            raise("len of dels and proof.targets differ")

        root_candidates = calculate_roots(self.numleaves, dels, proof)
        root_idxs = getrootidxs(self.numleaves, proof.targets)

        if len(root_candidates) != len(root_idxs):
            raise("length of calculated roots from the proof and expected root count differ")

        for i, idx in enumerate(root_idxs):
            if self.roots[idx] != root_candidates[i]:
                raise("calculated roots from the proof and matched roots differ")

    def delete(self, proof: Proof):
        modified_roots = calculate_roots(self.numleaves, None, proof)
        root_idxs = getrootidxs(self.numleaves, proof.targets)
        for i, idx in enumerate(root_idxs):
            self.roots[idx] = modified_roots[i]


def getrootidxs(numleaves: int, positions: [int]) -> [int]:
    indexes = set()
    for pos in positions:
        idx = root_idx(numleaves, pos)
        indexes.add(idx) if idx is not None else None

    return sorted(list(indexes), reverse=True)


def root_idx(numleaves: int, position: int) -> int:
    cur_idx = 0
    for row in range(tree_rows(numleaves), -1, -1):
        if not root_present(numleaves, row): continue

        for r in range(row, -1, -1):
            start_pos = start_position_at_row(r, tree_rows(numleaves))
            start_pos += start_position_offset(cur_idx, r, numleaves)
            end_pos = start_pos+(1<<(row-r))
            if start_pos <= position and position < end_pos: return cur_idx

        cur_idx += 1


def start_position_at_row(row: int, total_rows: int):
    return (2<<total_rows) - (2 << (total_rows - row))


def start_position_offset(index: int, row: int, numleaves: int):
    offset = 0
    for i in range(index):
        offset += 2<<i

    m = tree_rows(numleaves) - (index+1)
    for _ in range(m-row):
        offset *= 2

    return offset


def parent_hash(left, right):
    if left is None: return right
    if right is None: return left
    return hashlib.new('sha512_256', left+right).digest()


def parent(pos: int, total_rows: int) -> int:
    return (pos >> 1) | (1 << total_rows)


def tree_rows(n: int) -> int:
    return 0 if n == 0 else (n - 1).bit_length()


def root_position(leaves: int, row: int, total_rows: int) -> int:
    mask = (2 << total_rows) - 1
    before = leaves & (mask << (row + 1))
    shifted = (before >> row) | (mask << (total_rows + 1 - row))
    return shifted & mask


def detect_row(position: int, total_rows: int) -> int:
    marker = 1 << total_rows
    h = 0
    while position & marker != 0:
        marker >>= 1
        h += 1

    return h


def root_present(numleaves: int, row: int) -> bool:
    return numleaves & (1 << row) != 0


def isroot(position: int, numleaves: int, total_rows: int) -> bool:
    row = detect_row(position, total_rows)
    rootpos = root_position(numleaves, row, total_rows)
    return root_present(numleaves, row) and rootpos == position


def is_left_sibling(position: int) -> bool:
    return position & 1 == 0


def right_sibling(position: int) -> int:
    return position | 1


def calculate_roots(numleaves: int, dels: [bytes], proof: Proof) -> [bytes]:
    if not proof.targets: return []

    position_hashes = {}
    for i, target in enumerate(proof.targets):
        position_hashes[target] = None if dels is None else dels[i]

    calculated_roots = []
    sortedTargets = sorted(proof.targets)
    while sortedTargets:
        pos = sortedTargets.pop(0)
        cur_hash = position_hashes.pop(pos)

        if isroot(pos, numleaves, tree_rows(numleaves)):
            calculated_roots.append(cur_hash)
            continue

        parent_pos, p_hash = parent(pos, tree_rows(numleaves)), bytes
        if sortedTargets and right_sibling(pos) == sortedTargets[0]:
            sib_pos = sortedTargets.pop(0)
            p_hash = parent_hash(cur_hash, position_hashes.pop(sib_pos))
        else:
            proofhash = proof.proof.pop(0)
            p_hash = parent_hash(cur_hash, proofhash) if is_left_sibling(pos) else parent_hash(proofhash, cur_hash)

        position_hashes[parent_pos] = p_hash
        bisect.insort(sortedTargets, parent_pos)

    return calculated_roots
