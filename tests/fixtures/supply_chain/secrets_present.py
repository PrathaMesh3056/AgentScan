# secrets_present.py — fixture for secret_scanner tests
# Contains high-entropy secrets that should be flagged.

import os

# High-entropy OpenAI-style key — should be flagged (entropy >> 3.5)
OPENAI_API_KEY = "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdefghij"

# High-entropy Anthropic-style key — should be flagged
ANTHROPIC_API_SECRET = "sk-ant-api03-xK9mP2nQ8vR4sT6uW0yB5cF7hJ1lN3oA"

# Use via environment variable — should NOT be flagged (no literal value)
SAFE_KEY = os.environ.get("MY_API_KEY", "")
