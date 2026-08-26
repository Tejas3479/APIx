# Security Policy

APIx takes the security of our project and users seriously.

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| 1.2.x   | :x:                |
| 1.1.x   | :x:                |
| 1.0.x   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a potential security vulnerability in APIx (such as an SSRF bypass, authentication flaw, or injection vector), please report it responsibly:

1. **Email us directly:** Send details to `security@APIx.dev` or submit a private vulnerability report via GitHub.
2. **Include details:**
   - Steps to reproduce the issue
   - Proof-of-concept payload or snippet
   - Potential impact of the vulnerability
   - Recommended mitigation if known

## Vulnerability Disclosure Process

- **Acknowledgment:** We will acknowledge receipt of your vulnerability report within 48 hours.
- **Assessment & Fix:** We will evaluate the impact and aim to produce a patch within 7 business days.
- **Public Disclosure:** Once a fix is released, we will publish a security advisory and credit the reporter (unless you prefer to remain anonymous).

## Security Best Practices for Self-Hosting

When running APIx in production, ensure you follow our security guidelines:

- **API Keys:** Never expose APIx to the public internet without specifying strong API keys via `API_KEYS`.
- **SSRF Protection:** Keep `DISABLE_SSRF_CHECK=false` in production to prevent unauthorized access to local/private network ranges.
- **CORS Configuration:** Restrict `CORS_ORIGINS` to trusted domains rather than relying on wildcard origins when credentials are involved.
- **Network Isolation:** Run APIx inside an isolated container network with limited egress permissions where appropriate.
