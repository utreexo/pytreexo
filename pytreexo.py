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

    def add(self, adds: [bytes]):
        for add in adds:
            for row in range(tree_rows(self.numleaves)+1):
                if (self.numleaves >> row) & 1 == 0:
                    break
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

        if len(root_idxs) != len(root_candidates):
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
    idx = 0
    for row in range(tree_rows(numleaves), -1, -1):
        if numleaves&(1<<row) == 0:
            continue
        pos = position
        for _ in range(row): pos = parent(pos, tree_rows(numleaves))
        if isroot(pos, numleaves, tree_rows(numleaves)):
            return idx
        idx += 1


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


def isroot(position: int, numleaves: int, total_rows: int) -> bool:
    row = detect_row(position, total_rows)
    rootpos = root_position(numleaves, row, total_rows)
    root_present = numleaves & (1 << row) != 0
    return root_present and rootpos == position


def calculate_roots(numleaves: int, dels: [bytes], proof: Proof) -> [bytes]:
    if not proof.targets:
        return []

    calculated_roots = []

    posHash = {}
    for i, target in enumerate(proof.targets):
        if dels is None:
            posHash[target] = None
        else:
            posHash[target] = dels[i]

    sortedTargets = sorted(proof.targets)
    while sortedTargets:
        pos = sortedTargets.pop(0)
        cur_hash = posHash[pos]
        del posHash[pos]

        if isroot(pos, numleaves, tree_rows(numleaves)):
            calculated_roots.append(cur_hash)
            continue

        parent_pos = parent(pos, tree_rows(numleaves))
        bisect.insort(sortedTargets, parent_pos)

        if sortedTargets and pos | 1 == sortedTargets[0]:
            sib_pos = sortedTargets.pop(0)
            posHash[parent_pos] = parent_hash(cur_hash, posHash[sib_pos])

            del posHash[sib_pos]
        else:
            proofhash = proof.proof.pop(0)

            if pos & 1 == 0:
                posHash[parent_pos] = parent_hash(cur_hash, proofhash)
            else:
                posHash[parent_pos] = parent_hash(proofhash, cur_hash)

    return calculated_roots
