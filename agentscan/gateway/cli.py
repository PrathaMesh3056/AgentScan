"""Small stdlib-only entry point for the separate gateway process."""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentscan-gateway")
    parser.add_argument(
        "command",
        nargs="?",
        choices=("serve", "verify", "policy", "reconcile"),
        help="gateway operation (implemented in subsequent phases)",
    )
    parser.add_argument("command_args", nargs=argparse.REMAINDER)
    return parser


def _build_policy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentscan-gateway policy")
    subparsers = parser.add_subparsers(dest="policy_command", required=True)

    sign_parser = subparsers.add_parser("sign", help="sign an unsigned policy object")
    sign_parser.add_argument("--policy", required=True, help="unsigned policy YAML file")
    sign_parser.add_argument("--private-key", required=True, help="Ed25519 private key PEM file")
    sign_parser.add_argument("--bundle-id", required=True)
    sign_parser.add_argument("--tenant", required=True)
    sign_parser.add_argument("--issued-at", required=True)
    sign_parser.add_argument("--expires-at", required=True)
    sign_parser.add_argument("--out", required=True, help="output signed bundle YAML file")

    verify_parser = subparsers.add_parser("verify", help="verify a signed policy bundle")
    verify_parser.add_argument("--bundle", required=True, help="signed policy bundle YAML file")
    verify_parser.add_argument("--public-key", required=True, help="Ed25519 public key PEM file")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if args.command is None:
        return
    if args.command != "policy":
        parser.error(f"{args.command} is not available yet")

    policy_parser = _build_policy_parser()
    policy_args = policy_parser.parse_args(args.command_args)
    from agentscan.gateway.policy import (
        PolicyError,
        sign_policy_file,
        verify_policy_file,
    )

    try:
        if policy_args.policy_command == "sign":
            sign_policy_file(
                policy_args.policy,
                policy_args.private_key,
                bundle_id=policy_args.bundle_id,
                tenant=policy_args.tenant,
                issued_at=policy_args.issued_at,
                expires_at=policy_args.expires_at,
                output_path=policy_args.out,
            )
            print(f"signed bundle: {policy_args.out}")
        else:
            verified = verify_policy_file(policy_args.bundle, policy_args.public_key)
            print(f"policy_hash={verified.policy_hash}")
            print(f"key_id={verified.key_id}")
    except (PolicyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
