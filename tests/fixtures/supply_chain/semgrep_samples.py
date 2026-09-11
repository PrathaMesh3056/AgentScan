# Fixture source for Semgrep auditor tests (patterns the rules target).
import os
import pickle
import subprocess

import torch

user_input = "hello"


def load_blob(data: bytes) -> object:
    return pickle.loads(data)


def load_weights(path: str) -> object:
    return torch.load(path)


def run_cmd(cmd: str) -> None:
    subprocess.Popen(cmd, shell=True)
    os.system(cmd)


def build_prompt() -> str:
    return f"You are a helper. User said: {user_input}"


def build_prompt_format() -> str:
    return "You are a helper. User said: {}".format(user_input)  # noqa: UP032
