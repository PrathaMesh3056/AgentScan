# no_secrets.py — fixture for secret_scanner tests
# Only uses os.environ — no hardcoded secrets.

import os

# Safe: loaded from environment, not hardcoded
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
ANTHROPIC_API_SECRET = os.environ.get("ANTHROPIC_API_SECRET", "")

# Low-entropy placeholder — should NOT be flagged (entropy < 3.5)
# (This assignment pattern matches the regex but has low entropy)
DEBUG_TOKEN = "password123"
