# Fixture containing all Semgrep AI security rule patterns for native AST engine testing.
import os
import pickle
import sqlite3
import subprocess

import joblib
import numpy as np
import torch

user_input = "malicious input"


def test_pickle(data: bytes) -> object:
    return pickle.loads(data)


def test_torch_unsafe(path: str) -> object:
    return torch.load(path)


def test_torch_safe(path: str) -> object:
    return torch.load(path, weights_only=True)


def test_subprocess_unsafe(cmd: str) -> None:
    subprocess.Popen(cmd, shell=True)
    subprocess.run(cmd, shell=True)


def test_subprocess_safe(cmd: list[str]) -> None:
    subprocess.run(cmd, shell=False)


def test_system(cmd: str) -> None:
    os.system(cmd)


def test_eval_exec(code: str) -> None:
    eval(code)  # noqa: S307
    exec(code)  # noqa: S102


def test_numpy_unsafe(path: str) -> object:
    return np.load(path, allow_pickle=True)


def test_numpy_safe(path: str) -> object:
    return np.load(path, allow_pickle=False)


def test_joblib(path: str) -> object:
    return joblib.load(path)


def test_sql_unsafe(conn: sqlite3.Connection, name: str) -> None:
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")


def test_sql_safe(conn: sqlite3.Connection, name: str) -> None:
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))


def test_prompt_fstring() -> str:
    return f"You are a helpful assistant. User prompt: {user_input}"


def test_prompt_format() -> str:
    template = "System instructions. User query: {}"
    return template.format(user_input)
