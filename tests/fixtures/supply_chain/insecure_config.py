# insecure_config.py — fixture for config_auditor tests
# Contains all three dangerous patterns:
#   1. torch.load without weights_only=True
#   2. allow_dangerous_deserialization=True
#   3. DEBUG = True

import torch
from langchain.document_loaders import UnstructuredFileLoader

# Pattern 1: torch.load without weights_only=True
model = torch.load("model_weights.pt")

# Pattern 2: allow_dangerous_deserialization
loader = UnstructuredFileLoader(
    "document.pdf",
    allow_dangerous_deserialization=True,
)

# Pattern 3: DEBUG flag
DEBUG = True
