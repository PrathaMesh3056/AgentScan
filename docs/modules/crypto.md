# API authentication and encryption

AgentScan uses Ed25519-signed API tokens and provides authenticated encryption
helpers. These are infrastructure components, not an attack module or an
automatic encryption vault for scan data.

## Configure authentication

Supply the API's Ed25519 private key through a key file or secret manager, and
protect it with the same care as other service credentials. The
[API setup guide](../api.md) documents configuration, required token claims,
tenant identity and token issuance. Former symmetric-key configuration is
unsupported; existing tokens must be reissued for the configured signing key.

Current key rotation invalidates existing tokens. Overlapping key rotation and
JWKS are not implemented. Deployments must arrange key storage, access control,
TLS and rotation for their environment.

## Encryption helpers

Integrations can use AES-256-GCM-SIV authenticated encryption, Argon2id key
derivation, secure random nonces and constant-time comparison. Decryption rejects
an invalid authentication tag. Callers remain responsible for key handling and
consistent associated data.

Choosing these primitives does not establish deployment compliance or guarantee
that every stored artifact is encrypted. Review the actual integration and
[architecture](../ARCHITECTURE.md) before making such claims.
