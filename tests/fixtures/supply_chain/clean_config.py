# clean_config.py — fixture for config_auditor tests
# No dangerous patterns — torch.load uses weights_only=True.

import torch

# Safe: weights_only=True prevents arbitrary code execution
model = torch.load("model_weights.pt", weights_only=True)

DEBUG = False
