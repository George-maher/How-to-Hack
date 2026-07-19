# Contributing to HowToHack

## Important Legal Notice

**HowToHack is proprietary commercial software.** By contributing to this
project, you agree to the following terms:

1. All contributions become the exclusive intellectual property of HowToHack.
2. You grant HowToHack a perpetual, irrevocable, worldwide, royalty-free
   license to use, modify, reproduce, and distribute your contributions.
3. You represent that you have the right to make the contribution.
4. No source code contributions from outside the core development team will
   be accepted without a signed Contributor License Agreement (CLA).
5. You agree not to introduce any code that violates third-party intellectual
   property rights.

## Contributor License Agreement

Before any contribution can be accepted, you must sign a Contributor License
Agreement (CLA). Contact legal@howtohack.dev to obtain the CLA.

## How to Contribute

### Reporting Bugs

- Use the GitHub Issues tracker (private repository).
- Include steps to reproduce, expected behavior, and actual behavior.
- Include environment details (OS, PHP version, Docker version).
- Mark sensitive information appropriately.

### Suggesting Features

- Describe the feature and its business value.
- Explain how it integrates with existing functionality.
- Provide examples of use cases.

### Security Vulnerabilities

**DO NOT** create a public GitHub issue for security vulnerabilities.
Email security@howtohack.dev immediately.

## Development Process

1. Internal developers work on feature branches.
2. All changes require code review.
3. Tests must pass before merging.
4. Documentation must be updated with changes.
5. Security review required for authentication/authz changes.

## Code Standards

- **PHP**: PSR-12, strict types, typed properties, constructor promotion
- **TypeScript**: Strict mode, interfaces for all data types
- **CSS**: CSS variables for theming, dark theme only
- **Architecture**: Follow existing Clean Architecture patterns

## Testing

```bash
cd backend && composer run test
cd frontend && npm run lint
```

## Contact

- Development team: dev@howtohack.dev
- Legal: legal@howtohack.dev
- Security: security@howtohack.dev
