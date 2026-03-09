# [ARCHIVED] Tinfoil Attestation Shim

### This repository has been archived.

**The shim has been merged into [cvmimage](https://github.com/tinfoilsh/cvmimage) at `tinfoil/cmd/shim/`.** All future development happens there.

---

A reverse proxy service that terminates TLS and exposes the attestation attestation report over HTTP.

## Features

- TLS termination with automatic certificate management
- AMD SEV-SNP / Intel TDX attestation endpoint
- API key validation through an external key server
- Rate limiting per API key
- Path-based access control

## Attestation

The shim provides an attestation endpoint at `/.well-known/tinfoil-attestation` that returns a signed attestation report.
The report includes a SHA-256 hash of the TLS certificate in the user data field, allowing clients to bind a TLS connection to an enclave measurement.

## Authorization and Control Plane Integration

For each every request to the upstream (the attestation endpoint is excluded from authorization), the shim will check if the `Authorization: Bearer ...` header is set and attempt to verify the token agains the configured public key.
