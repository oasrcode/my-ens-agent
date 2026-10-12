"""Vulnerable fixture: hardcoded credentials, tokens and private key material."""

# AWS access key id (documented example prefix, 20 chars total).
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# A hardcoded database password.
DATABASE_PASSWORD = "Sup3rS3cret-Pa$$w0rd"

# An inlined PEM private key.
PRIVATE_KEY_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE
-----END RSA PRIVATE KEY-----"""

# A signed session token (JWT).
SESSION_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
