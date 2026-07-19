# Security Policy

## Supported Versions

| Version | Supported | Commercial Support |
|---------|-----------|-------------------|
| 1.x     | ✅        | ✅ Enterprise     |

## Reporting a Vulnerability

We take the security of HowToHack seriously. If you discover a security
vulnerability, please follow these steps:

1. **Do NOT** disclose the vulnerability publicly (e.g., via GitHub Issues).
2. **Do NOT** create a public pull request with the fix.
3. Send a detailed description to **security@howtohack.dev**.
4. Include steps to reproduce, affected versions, and potential impact.
5. Allow us 30 days to investigate and address the issue before disclosure.

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Responsible Disclosure

We appreciate responsible disclosure of security vulnerabilities. Security
researchers who report valid vulnerabilities will be acknowledged (with
permission) in our release notes.

## Commercial Security Support

Enterprise license holders receive:
- Priority security issue handling
- Direct access to security team
- Custom SLA agreements
- Security patches outside regular release cycle
- Vulnerability assessment assistance

## Security Best Practices

### For License Holders

1. **API Keys**: Never commit API keys (OpenAI, Claude, OpenRouter) to
   version control. Use environment variables or a secrets manager.

2. **Database**: Use strong, unique passwords for database connections.
   Never use default credentials in production.

3. **Docker Deployment**:
   - Use environment variables, never hardcoded secrets
   - Restrict container network access
   - Use Docker secrets or a vault for production
   - Enable container security scanning

4. **Authentication**:
   - Change default credentials immediately
   - Enforce strong password policies
   - Enable two-factor authentication if available
   - Use HTTPS exclusively in production

5. **Network Security**:
   - Place behind a reverse proxy with TLS termination
   - Configure proper firewall rules
   - Use a WAF for production deployments
   - Restrict API access by IP if possible

6. **Data Protection**:
   - Encrypt data at rest
   - Use encrypted backups
   - Implement data retention policies
   - Regularly purge old scan results

7. **Audit Logging**:
   - Enable comprehensive audit logging
   - Monitor for suspicious activity
   - Retain logs per regulatory requirements

### Specific to This Software

8. **Scanner Safety**: Only scan targets you own or have explicit written
   permission to test. Unauthorized scanning may violate computer fraud laws.

9. **AI Provider API Keys**: Store AI provider API keys in a secrets manager
   or environment variables. Rotate keys regularly.

10. **Rate Limiting**: The API has built-in rate limiting (60 requests/minute).
    Adjust based on your deployment needs.

## Compliance

Enterprise deployments may require:
- SOC 2 compliance documentation
- GDPR data processing agreement
- HIPAA BA agreement (for healthcare)
- PCI DSS compliance support

Contact enterprise@howtohack.dev for compliance documentation.

## Scope

This security policy covers the HowToHack application code and its direct
dependencies. Third-party tools (nmap, nuclei, nikto, etc.) have their own
security policies and should be updated independently.

## Contact

- Security issues: security@howtohack.dev
- Enterprise support: enterprise@howtohack.dev
- General inquiries: legal@howtohack.dev
