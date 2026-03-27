# Security Policy

## Scope

This project may process private source code and repository access credentials.
Treat all tokens, reports, and synced repositories as sensitive data.

## Mandatory Baseline

1. Keep Git repositories private and enforce least-privilege access.
2. Never commit `.env`, database files, reports, or synced repository snapshots.
3. Rotate all leaked tokens immediately.
4. Deliver to external parties using private Docker images instead of full source code.
5. Require signed NDA + software license agreement before any source sharing.

## Secret Leakage Prevention

Use pre-commit hooks to block common token patterns before commit:

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files
```

## Incident Response

If a credential is exposed:

1. Revoke token immediately in platform console.
2. Create a new token with minimum required scopes.
3. Replace server/runtime configuration.
4. Review logs for unauthorized access.
5. Re-scan repository history for leaked credentials.
