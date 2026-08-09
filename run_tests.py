import unittest
import sys
import os

# Import the test suite
from tests.verification_harness import TestVulneraMapEnterprise

if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestVulneraMapEnterprise)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    if result.wasSuccessful():
        print("\nALL VULNERA-MAP ENTERPRISE VERIFICATION TESTS PASSED SUCCESSFULLY!")
        sys.exit(0)
    else:
        print("\nVerification test failures detected.")
        sys.exit(1)
