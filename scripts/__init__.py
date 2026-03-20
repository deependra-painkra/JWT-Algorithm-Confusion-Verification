"""
JWT Algorithm Confusion Verification Suite
Remediation verification tools for JWT algorithm confusion vulnerabilities
"""

__version__ = "1.0.0"
__author__ = "deependra-painkra"
__description__ = "Comprehensive JWT security testing framework"

# Import main modules for easy access
from .verify_jwt import (
    JWTTokenManipulator,
    JWTVerificationTester,
    generate_report,
    save_evidence,
)
from .generate_test_keys import generate_keys
from .generate_test_tokens import generate_all_tokens

__all__ = [
    'JWTTokenManipulator',
    'JWTVerificationTester',
    'generate_report',
    'save_evidence',
    'generate_keys',
    'generate_all_tokens',
]
