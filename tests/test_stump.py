import hashlib
import json
import pytreexo
import unittest


class TestStump(unittest.TestCase):
    def test_add(self):
        with open("tests/test_cases.json") as f:
            data = json.load(f)
            for test in data['insertion_tests']:
                leaves = [x.to_bytes(1, byteorder='big') for x in test['leaf_preimages']]
                hashed_leaves = [hashlib.sha256(leaf).digest() for leaf in leaves]

                s = pytreexo.Stump()
                s.add(hashed_leaves)

                for i, expected_str in enumerate(test['expected_roots']):
                    expected = bytes.fromhex(expected_str)
                    root = s.roots[i]
                    assert(root == expected)

    def test_verify(self):
        with open("tests/test_cases.json") as f:
            data = json.load(f)
            for i, test in enumerate(data['proof_tests']):
                s = pytreexo.Stump()
                s.numleaves = test['numleaves']
                s.roots = [bytes.fromhex(root_str) for root_str in test['roots']]

                proofhashes = [bytes.fromhex(proof_str) for proof_str in test['proofhashes']]
                proof = pytreexo.Proof(test['targets'], proofhashes)

                preimages = [preimage.to_bytes(1, byteorder='big') for preimage in test['target_preimages']]
                del_hashes = [hashlib.sha256(preimage).digest() for preimage in preimages]
                try:
                    s.verify(del_hashes, proof)
                except:
                    if test['expected'] is True:
                        raise("expected the {}th proof to pass".format(i))
                else:
                    if test['expected'] is False:
                        raise("expected the proof to error out. Reason {}".format(test['reason']))

    def test_delete(self):
        with open("tests/test_cases.json") as f:
            data = json.load(f)
            for i, test in enumerate(data['deletion_tests']):
                leaves = [x.to_bytes(1, byteorder='big') for x in test['leaf_preimages']]
                hashed_leaves = [hashlib.sha256(leaf).digest() for leaf in leaves]

                s = pytreexo.Stump()
                s.add(hashed_leaves)

                preimages = [preimage.to_bytes(1, byteorder='big') for preimage in test['target_values']]
                del_hashes = [hashlib.sha256(preimage).digest() for preimage in preimages]

                proofhashes = [bytes.fromhex(proof_str) for proof_str in test['proofhashes']]
                proof = pytreexo.Proof(test['target_values'], proofhashes)
                s.delete(proof)

                for i, expected_str in enumerate(test['expected_roots']):
                    root = s.roots[i]
                    if expected_str == "0000000000000000000000000000000000000000000000000000000000000000":
                        assert(root is None)
                    else:
                        expected = bytes.fromhex(expected_str)
                        assert(root == expected)


if __name__ == '__main__':
    unittest.main()
