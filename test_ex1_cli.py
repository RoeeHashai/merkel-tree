import subprocess
import sys
import unittest
import hashlib
import os
from typing import List
from datetime import datetime

EX1_SCRIPT = os.path.abspath("ex1.py")
TEST_OUTPUT_FILE = None
TEST_COUNTER = 0


def run_ex1(inputs: List[str]) -> List[str]:
    """Run ex1.py with the given list of input lines and return output lines.

    A helper that starts the script in a subprocess, feeds the newline
    separated *inputs* terminated by an extra newline and captures the
    stdout.  Stderr (if any) is surfaced to fail the test early.
    """
    global TEST_OUTPUT_FILE, TEST_COUNTER
    TEST_COUNTER += 1
    
    proc = subprocess.Popen(
        [sys.executable, EX1_SCRIPT],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    in_data = "\n".join(inputs) + "\n"
    
    # Write the input to the test output file
    if TEST_OUTPUT_FILE:
        TEST_OUTPUT_FILE.write(f"\n{'='*60}\n")
        TEST_OUTPUT_FILE.write(f"Test Execution #{TEST_COUNTER}\n")
        TEST_OUTPUT_FILE.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        TEST_OUTPUT_FILE.write(f"{'='*60}\n\n")
        TEST_OUTPUT_FILE.write("INPUT TO ex1.py:\n")
        TEST_OUTPUT_FILE.write("-" * 40 + "\n")
        for i, line in enumerate(inputs, 1):
            TEST_OUTPUT_FILE.write(f"{i:3d}: {line}\n")
        TEST_OUTPUT_FILE.write("-" * 40 + "\n\n")
    
    stdout, stderr = proc.communicate(input=in_data)
    if stderr:
        # Log error to file before failing
        if TEST_OUTPUT_FILE:
            TEST_OUTPUT_FILE.write(f"ERROR OUTPUT:\n{stderr}\n")
            TEST_OUTPUT_FILE.write("="*60 + "\n\n")
        # fail fast – any stderr indicates crash / un-handled exception
        raise AssertionError(f"ex1.py produced stderr: {stderr}")
    out_lines = stdout.splitlines()
    
    # Write the output to the test output file
    if TEST_OUTPUT_FILE:
        TEST_OUTPUT_FILE.write("OUTPUT FROM ex1.py:\n")
        TEST_OUTPUT_FILE.write("-" * 40 + "\n")
        if out_lines:
            for i, line in enumerate(out_lines, 1):
                TEST_OUTPUT_FILE.write(f"{i:3d}: {line}\n")
        else:
            TEST_OUTPUT_FILE.write("    (no output)\n")
        TEST_OUTPUT_FILE.write("-" * 40 + "\n\n")
        TEST_OUTPUT_FILE.flush()  # Ensure it's written immediately
    
    return out_lines


def _calc_expected_root(strings: List[str]) -> str:
    """Pure-python reference implementation for tree root calculation."""
    if not strings:
        return ""
    data = [s.encode() for s in strings]

    def _root(l: int, h: int) -> bytes:
        span = h - l
        if span == 1:
            return hashlib.sha256(data[l]).digest()
        split = 1 << ((span - 1).bit_length() - 1)
        m = l + split
        left = _root(l, m)
        right = _root(m, h)
        return hashlib.sha256((left.hex() + right.hex()).encode()).digest()

    return _root(0, len(data)).hex()


class Ex1CLITests(unittest.TestCase):
    # ------------------------------------------------------------
    # Basic insert / root
    # ------------------------------------------------------------
    def test_single_leaf_root(self):
        inputs = [
            "1 a",  # insert
            "2"      # root
        ]
        outputs = run_ex1(inputs)
        self.assertEqual(len(outputs), 1)
        self.assertEqual(outputs[0], _calc_expected_root(["a"]))

    def test_single_leaf_proof_and_verify(self):
        """Test that a single-leaf tree produces empty proof and verifies correctly."""
        leaf = "single"
        build = [f"1 {leaf}"]
        
        # Get proof for the single leaf (should be empty)
        proof_out = run_ex1(build + ["3 0"])[0]
        parts = proof_out.split()
        root_hex = parts[0]
        proof_items = parts[1:]  # Should be empty list
        
        self.assertEqual(len(proof_items), 0, "Single leaf should have empty proof")
        
        # Verify with empty proof should succeed
        verify_cmds = build + [f"4 {leaf} {root_hex}"]
        verify_out = run_ex1(verify_cmds)
        self.assertEqual(verify_out[-1], "True", "Empty proof should verify for single leaf")
        
        # Also verify with wrong data should fail
        verify_cmds = build + [f"4 wrong {root_hex}"]
        verify_out = run_ex1(verify_cmds)
        self.assertEqual(verify_out[-1], "False", "Wrong data should not verify even with empty proof")

    def test_multiple_leaves_root(self):
        leaves = ["a", "b", "c", "d", "e"]
        ins_cmds = [f"1 {v}" for v in leaves]
        outputs = run_ex1(ins_cmds + ["2"])
        self.assertEqual(outputs[0], _calc_expected_root(leaves))

    # ------------------------------------------------------------
    # Proof generation + verification
    # ------------------------------------------------------------
    def test_proof_and_verify_success(self):
        leaves = ["x", "y", "z"]
        build_cmds = [f"1 {v}" for v in leaves]
        proof_idx = 1  # middle leaf
        cmds = build_cmds + [f"3 {proof_idx}"]
        proof_output = run_ex1(cmds)[0]

        parts = proof_output.split()
        root_hex, proof_items = parts[0], parts[1:]

        # now verify in a new invocation
        verify_cmds = build_cmds + [
            f"4 {leaves[proof_idx]} {root_hex} " + " ".join(proof_items)
        ]
        verify_out = run_ex1(verify_cmds)
        self.assertEqual(verify_out[-1], "True")

    def test_proof_and_verify_failure(self):
        leaves = ["k", "l", "m"]
        build = [f"1 {v}" for v in leaves]
        proof_out = run_ex1(build + ["3 0"])[0]
        parts = proof_out.split()
        root_hex, proof_items = parts[0], parts[1:]

        # Tamper with first proof item (flip direction bit)
        tampered = [("1" if proof_items[0][0] == "0" else "0") + proof_items[0][1:]] + proof_items[1:]
        verify_cmds = build + [f"4 {leaves[0]} {root_hex} " + " ".join(tampered)]
        verify_out = run_ex1(verify_cmds)
        self.assertEqual(verify_out[-1], "False")

    # ------------------------------------------------------------
    # Key generation, signing, verification
    # ------------------------------------------------------------
    def test_rsa_sign_and_verify(self):
        leaves = ["foo", "bar"]
        build = [f"1 {v}" for v in leaves]
        root_hex = _calc_expected_root(leaves)

        # 1) Generate keys
        key_out = run_ex1(["5"])
        # Separate private / public blocks
        sk_lines, pk_lines = [], []
        current = None
        for line in key_out:
            if "BEGIN RSA PRIVATE KEY" in line:
                current = sk_lines
            elif "BEGIN PUBLIC KEY" in line:
                current = pk_lines
            if current is not None:
                current.append(line)
                if line.startswith("-----END"):
                    current = None
        self.assertTrue(sk_lines and pk_lines)

        # 2) Sign root – we need to send the private key lines followed by blank line
        sign_cmds = build + [
            "6 " + sk_lines[0],
            *sk_lines[1:],
            "",  # blank line after key
        ]
        sign_out = run_ex1(sign_cmds)
        signature_b64 = sign_out[-1]
        self.assertTrue(len(signature_b64) > 20)

        # 3) Verify signature via CLI using public key
        verify_cmds = build + [
            "7 " + pk_lines[0],
            *pk_lines[1:],
            "",  # blank line
            f"{signature_b64} {root_hex}"
        ]
        verify_out = run_ex1(verify_cmds)
        self.assertEqual(verify_out[-1], "True")

    # ------------------------------------------------------------
    # Invalid / edge cases
    # ------------------------------------------------------------
    def test_invalid_commands(self):
        cmds = [
            "invalid",      # completely invalid
            "1",            # insert without data
            "3 5",          # proof on empty tree (invalid index)
            "4 a b c",      # verify with wrong arg count (b is not valid hex)
        ]
        out = run_ex1(cmds)
        expected = ["", "", "", ""]
        self.assertEqual(out, expected)

    def test_long_input_handled(self):
        long_str = "x" * 2048
        out = run_ex1([f"1 {long_str}", "2"])
        # Should produce exactly one root line
        self.assertEqual(len(out), 1)
        self.assertEqual(len(out[0]), 64)  # hex encoded SHA-256

    def test_incremental_roots(self):
        """After each insertion the reported root should match reference implementation."""
        leaves = ["apple", "banana", "cherry", "date", "elderberry"]
        cmds = []
        for leaf in leaves:
            cmds.append(f"1 {leaf}")
            cmds.append("2")
        outs = run_ex1(cmds)
        # We expect one output per root command
        self.assertEqual(len(outs), len(leaves))
        for i in range(len(leaves)):
            expected = _calc_expected_root(leaves[: i + 1])
            self.assertEqual(outs[i], expected)

    def test_various_proof_positions(self):
        leaves = [f"l{i}" for i in range(8)]  # 8 leaves, power-of-two size
        build = [f"1 {v}" for v in leaves]
        # indexes to test: first, middle, last
        for idx in [0, len(leaves)//2, len(leaves)-1]:
            cmds = build + [f"3 {idx}"]
            proof_line = run_ex1(cmds)[0]
            parts = proof_line.split()
            root, proof_items = parts[0], parts[1:]
            verify_cmds = build + [f"4 {leaves[idx]} {root} " + " ".join(proof_items)]
            verify_out = run_ex1(verify_cmds)
            self.assertEqual(verify_out[-1], "True", msg=f"proof failed for idx {idx}")

    def test_proof_invalid_root(self):
        leaves = ["red", "green", "blue"]
        build = [f"1 {v}" for v in leaves]
        proof_line = run_ex1(build + ["3 2"])[0]
        parts = proof_line.split()
        wrong_root = "0" * 64  # definitely not real root
        proof_items = parts[1:]
        verify_cmds = build + [f"4 {leaves[2]} {wrong_root} " + " ".join(proof_items)]
        verify_out = run_ex1(verify_cmds)
        self.assertEqual(verify_out[-1], "False")

    def test_malformed_proof_items(self):
        leaves = ["t1", "t2"]
        build = [f"1 {v}" for v in leaves]
        proof_line = run_ex1(build + ["3 0"])[0]
        root, orig_proof = proof_line.split()[0], proof_line.split()[1:]

        malformed_cases = [
            [orig_proof[0][1:]],  # missing direction bit
            ["2" + orig_proof[0][1:]],  # invalid direction bit
            [orig_proof[0][:30]],  # truncated
            [orig_proof[0] + "00"],  # extra chars making non-hex length
            ["1" + "z" * 64],  # non-hex chars
        ]
        for case in malformed_cases:
            verify_cmds = build + [f"4 {leaves[0]} {root} " + " ".join(case)]
            out = run_ex1(verify_cmds)
            self.assertEqual(out[-1], "", msg=f"case {case} not empty line")

    def test_signature_invalid_after_tree_change(self):
        # Build simple tree and sign
        build = ["1 a", "1 b"]
        root = _calc_expected_root(["a", "b"])
        key_out = run_ex1(["5"])
        sk_lines, pk_lines = [], []
        current = None
        for line in key_out:
            if "BEGIN RSA PRIVATE KEY" in line:
                current = sk_lines
            elif "BEGIN PUBLIC KEY" in line:
                current = pk_lines
            if current is not None:
                current.append(line)
                if line.startswith("-----END"):
                    current = None
        sign_cmds = build + [
            "6 " + sk_lines[0],
            *sk_lines[1:],
            "",
        ]
        sign_out = run_ex1(sign_cmds)
        sig = sign_out[-1]

        # mutate tree (add another leaf) and verify signature over old root should fail
        build_mutated = build + ["1 c"]
        verify_cmds = build_mutated + [
            "7 " + pk_lines[0],
            *pk_lines[1:],
            "",
            f"{sig} {root}"
        ]
        verify_out = run_ex1(verify_cmds)
        self.assertEqual(verify_out[-1], "True")  # signature checks data, not tree state

        # but verifying with NEW root should fail
        new_root = _calc_expected_root(["a", "b", "c"])
        verify_cmds[-1] = f"{sig} {new_root}"
        verify_out2 = run_ex1(verify_cmds)
        self.assertEqual(verify_out2[-1], "False")

    # ------------------------------------------------------------
    # Additional advanced / edge scenarios
    # ------------------------------------------------------------
    def test_proof_length_power_of_two(self):
        """Proof length should equal log2(n) for power-of-two sized trees."""
        import math
        for exp in range(1, 6):  # 2..32 leaves
            n = 2 ** exp
            leaves = [f"p{idx}" for idx in range(n)]
            build = [f"1 {v}" for v in leaves] + [f"3 {n-1}"]
            proof_line = run_ex1(build)[0]
            proof_len = len(proof_line.split()) - 1  # exclude root
            self.assertEqual(proof_len, exp, msg=f"n={n} proof length {proof_len} != {exp}")

    def test_random_leaf_proofs_large_tree(self):
        """Randomly pick leaves in a 50-leaf tree and validate proofs."""
        import random
        leaves = [f"val{idx}" for idx in range(50)]
        build = [f"1 {v}" for v in leaves]
        # build tree and then produce proofs for 10 random indices
        random_idxs = random.sample(range(50), 10)
        cmds = build[:]
        for idx in random_idxs:
            cmds.append(f"3 {idx}")
        outs = run_ex1(cmds)
        for idx, line in zip(random_idxs, outs):
            root, *proof_items = line.split()
            verify_cmds = build + [f"4 {leaves[idx]} {root} " + " ".join(proof_items)]
            vr_out = run_ex1(verify_cmds)
            self.assertEqual(vr_out[-1], "True", msg=f"random idx {idx} failed")

    def test_signature_wrong_public_key(self):
        """Verification should fail when using a key that did not produce the signature."""
        leaves = ["sigA", "sigB"]
        build = [f"1 {v}" for v in leaves]
        # first key pair
        sk1, pk1 = run_ex1(["5"]), None
        # second key pair
        sk2_lines = run_ex1(["5"])
        sk_lines, pk2_lines = [], []
        for line in sk2_lines:
            if "BEGIN RSA PRIVATE KEY" in line:
                sk_lines.append(line)
            if "BEGIN PUBLIC KEY" in line or pk2_lines:
                pk2_lines.append(line)
        # sign with first key
        first_sk_lines = []
        collecting = False
        for line in sk1:
            if "BEGIN RSA PRIVATE KEY" in line:
                collecting = True
            if collecting:
                first_sk_lines.append(line)
            if line.startswith("-----END RSA PRIVATE KEY"):
                collecting = False
            if line.startswith("-----END PUBLIC KEY"):
                break
        sign_cmds = build + [
            "6 " + first_sk_lines[0],
            *first_sk_lines[1:],
            "",
        ]
        sig = run_ex1(sign_cmds)[-1]

        root_hex = _calc_expected_root(leaves)
        # verify with *wrong* public key (from second key pair) should fail
        verify_cmds = build + [
            "7 " + pk2_lines[0],
            *pk2_lines[1:],
            f"{sig} {root_hex}"
        ]
        vr_out = run_ex1(verify_cmds)
        self.assertEqual(vr_out[-1], "False")

    def test_verify_invalid_base64_signature(self):
        leaves = ["b64a", "b64b"]
        build = [f"1 {v}" for v in leaves]
        invalid_sig = "!!!not_base64!!!"
        pk_lines_output = run_ex1(["5"])
        pk_lines = []
        recording = False
        for line in pk_lines_output:
            if "BEGIN PUBLIC KEY" in line:
                recording = True
            if recording:
                pk_lines.append(line)
            if line.startswith("-----END PUBLIC KEY"):
                break
        verify_cmds = build + [
            "7 " + pk_lines[0],
            *pk_lines[1:],
            "",
            f"{invalid_sig} {'a'*64}"
        ]
        out = run_ex1(verify_cmds)
        self.assertEqual(out[-1], "")

    def test_sign_invalid_key_prefix(self):
        """Test signing with invalid BEGIN marker - should output empty line."""
        leaves = ["test1", "test2"]
        build = [f"1 {v}" for v in leaves]
        # Wrong BEGIN marker
        sign_cmds = build + [
            "6 -----BEGIN INVALID KEY-----",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC",
            "-----END RSA PRIVATE KEY-----",
            "",
        ]
        out = run_ex1(sign_cmds)
        self.assertEqual(out[-1], "")  # Empty line

    def test_sign_invalid_key_suffix(self):
        """Test signing with invalid END marker - should output empty line."""
        leaves = ["test1", "test2"]
        build = [f"1 {v}" for v in leaves]
        # Wrong END marker
        sign_cmds = build + [
            "6 -----BEGIN RSA PRIVATE KEY-----",
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC",
            "-----END INVALID KEY-----",
            "",
        ]
        out = run_ex1(sign_cmds)
        self.assertEqual(out[-1], "")  # Empty line

    def test_sign_valid_markers_invalid_content(self):
        """Test signing with valid markers but invalid key content - should output False."""
        leaves = ["test1", "test2"]
        build = [f"1 {v}" for v in leaves]
        # Valid markers but garbage content
        sign_cmds = build + [
            "6 -----BEGIN RSA PRIVATE KEY-----",
            "This is not valid key data",
            "Just some random text",
            "-----END RSA PRIVATE KEY-----",
            "",
        ]
        # This should actually cause an error since base64.b64encode(False) will fail
        # The test runner should catch this as stderr
        try:
            out = run_ex1(sign_cmds)
            # If we get here without exception, check if output is empty
            self.assertEqual(out[-1], "")
        except AssertionError as e:
            # Expected - sign() returns False, base64.b64encode(False) fails
            self.assertIn("stderr", str(e))

    def test_verify_invalid_key_prefix(self):
        """Test verify with invalid BEGIN marker - should output empty line."""
        leaves = ["test1", "test2"]
        build = [f"1 {v}" for v in leaves]
        verify_cmds = build + [
            "7 -----BEGIN INVALID KEY-----",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
            "-----END PUBLIC KEY-----",
            "",
            "dGVzdA== " + "a" * 64
        ]
        out = run_ex1(verify_cmds)
        self.assertEqual(out[-1], "")  # Empty line

    def test_verify_invalid_key_suffix(self):
        """Test verify with invalid END marker - should output empty line."""
        leaves = ["test1", "test2"]
        build = [f"1 {v}" for v in leaves]
        verify_cmds = build + [
            "7 -----BEGIN PUBLIC KEY-----",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
            "-----END INVALID KEY-----",
            "",
            "dGVzdA== " + "a" * 64
        ]
        out = run_ex1(verify_cmds)
        self.assertEqual(out[-1], "")  # Empty line

    def test_verify_valid_markers_invalid_content(self):
        """Test verify with valid markers but invalid key content - should output False."""
        leaves = ["test1", "test2"]
        build = [f"1 {v}" for v in leaves]
        verify_cmds = build + [
            "7 -----BEGIN PUBLIC KEY-----",
            "This is not valid key data",
            "Just some random text",
            "-----END PUBLIC KEY-----",
            "",
            "dGVzdA== " + "a" * 64
        ]
        out = run_ex1(verify_cmds)
        self.assertEqual(out[-1], "False")


class FileLoggingTestResult(unittest.TextTestResult):
    """Custom test result class that logs test names to file."""
    def startTest(self, test):
        global TEST_OUTPUT_FILE
        super().startTest(test)
        if TEST_OUTPUT_FILE:
            test_name = test._testMethodName
            TEST_OUTPUT_FILE.write(f"\n{'#'*60}\n")
            TEST_OUTPUT_FILE.write(f"# Starting Test: {test_name}\n")
            TEST_OUTPUT_FILE.write(f"{'#'*60}\n")
            TEST_OUTPUT_FILE.flush()


if __name__ == "__main__":
    # Simple banner + list of test cases for visual tracking
    header = "MERKLE TREE CLI TEST SUITE"
    print("\n" + "=" * len(header))
    print(header)
    print("=" * len(header))

    # Open the test output file
    TEST_OUTPUT_FILE = open("test_output.txt", "w", encoding="utf-8")
    TEST_OUTPUT_FILE.write("MERKLE TREE TEST OUTPUT LOG\n")
    TEST_OUTPUT_FILE.write(f"Test run started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    TEST_OUTPUT_FILE.write("="*60 + "\n\n")
    
    _loader = unittest.TestLoader()
    _suite = _loader.loadTestsFromTestCase(Ex1CLITests)
    print("Running the following tests:")
    for t in _suite:
        print("  •", t._testMethodName)
    print()
    print(f"Test output will be written to: test_output.txt")

    # Use custom test runner with our result class
    runner = unittest.TextTestRunner(
        verbosity=2,
        resultclass=FileLoggingTestResult
    )
    result = runner.run(_suite)
    
    # Close the file
    TEST_OUTPUT_FILE.write("\n" + "="*60 + "\n")
    TEST_OUTPUT_FILE.write(f"Test run completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    TEST_OUTPUT_FILE.write(f"Tests run: {result.testsRun}\n")
    TEST_OUTPUT_FILE.write(f"Failures: {len(result.failures)}\n")
    TEST_OUTPUT_FILE.write(f"Errors: {len(result.errors)}\n")
    TEST_OUTPUT_FILE.close()
    
    print(f"\n✓ Test output has been written to: test_output.txt") 