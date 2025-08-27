"""
Test runner for the SOC platform components.
"""

import unittest
import argparse
import sys
import os
from pathlib import Path

# Add the project root to the Python path
PROJECT_ROOT = str(Path(__file__).parent.absolute())
sys.path.insert(0, PROJECT_ROOT)

def run_tests(test_names=None, verbosity=2):
    """Run the specified tests.
    
    Args:
        test_names: List of test names to run (e.g., ['test_component_imports'])
        verbosity: Verbosity level (0=quiet, 1=normal, 2=verbose)
    """
    # Create test suite
    if test_names:
        # Run specific tests
        test_suite = unittest.TestSuite()
        for test_name in test_names:
            test_suite.addTest(TestSOCComponents(test_name))
    else:
        # Run all tests
        test_suite = unittest.TestLoader().loadTestsFromTestCase(TestSOCComponents)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=verbosity)
    result = runner.run(test_suite)
    
    # Return appropriate exit code
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run SOC component tests.')
    parser.add_argument(
        'tests', 
        nargs='*',
        help='Specific test names to run (e.g., test_component_imports)'
    )
    parser.add_argument(
        '-v', '--verbosity',
        type=int,
        default=2,
        help='Verbosity level (0=quiet, 1=normal, 2=verbose)'
    )
    
    args = parser.parse_args()
    
    # Import test cases after setting up paths
    from tests.test_components import TestSOCComponents
    
    # Run tests
    sys.exit(run_tests(args.tests, args.verbosity))
