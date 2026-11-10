"""Small stdlib-only entry point for the separate gateway process."""

from __future__ import annotations

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentscan-gateway")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("serve", "verify", "policy", "reconcile"),
        help="gateway operation (implemented in subsequent phases)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command is not None:
        parser.error(f"{args.command} is not available in the Phase 0 skeleton")
