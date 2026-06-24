# Contributing to Shadowgram

Thank you for considering contributing to Shadowgram! We welcome all contributions that help improve the project.

## Code of Conduct

### Our Pledge

1. **No Backdoors** - Any code intended to weaken security will be rejected immediately.
2. **Transparency** - All changes must be reviewable and auditable.
3. **Respect** - Treat all contributors with respect and openness.
4. **Privacy First** - User privacy is the top priority in all decisions.

### Our Standards

Examples of behavior that contributes to a positive environment:
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community

Examples of unacceptable behavior:
- The use of sexualized language or imagery
- Trolling, insulting/derogatory comments
- Public or private harassment
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

## Security Contributions

### Reporting Vulnerabilities

**DO NOT** create public GitHub issues for security vulnerabilities.

Instead, email: **security@shadowgram.org** (placeholder - update before release)

See [SECURITY.md](SECURITY.md) for the full security policy.

### Security Code Guidelines

When contributing code:

1. **Zeroize Secrets** - All key material must be zeroized on drop
   ```rust
   use zeroize::Zeroize;

   struct SecretKey {
       key: [u8; 32],
   }

   impl Zeroize for SecretKey {
       fn zeroize(&mut self) {
           self.key.zeroize();
       }
   }
   ```

2. **Constant-Time Comparisons** - Use `subtle` crate for secret data
   ```rust
   use subtle::ConstantTimeEq;

   fn verify_mac(mac1: &[u8], mac2: &[u8]) -> bool {
       mac1.ct_eq(mac2).into()
   }
   ```

3. **No Unsafe Code Without Justification** - Avoid `unsafe` unless necessary
4. **Validate All Input** - Never trust external input
5. **Fail Securely** - Default to denial on errors

## How to Contribute

### Development Setup

1. Fork the repository
2. Clone your fork
   ```bash
   git clone https://github.com/your-username/shadowgram.git
   cd shadowgram
   ```
3. Create a branch
   ```bash
   git checkout -b feature/your-feature
   ```
4. Make your changes
5. Run tests
   ```bash
   cargo test
   cargo clippy --all-targets -- -D warnings
   cargo fmt
   ```
6. Commit and push
   ```bash
   git commit -m "Add your feature"
   git push origin feature/your-feature
   ```
7. Open a Pull Request

### Commit Message Guidelines

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: Add new group chat feature
fix: Fix message ordering bug
docs: Update README with build instructions
test: Add integration tests for PSI
chore: Update dependencies
```

### Pull Request Process

1. **Create PR** - From your fork's branch to `main`
2. **Pass CI** - All checks must pass
3. **Code Review** - At least one maintainer must approve
4. **Security Review** - Security-sensitive changes need extra review
5. **Merge** - Maintainer will merge when ready

## Areas We Need Help

### High Priority

- [ ] **Security Audit** - Professional audit of crypto implementations
- [ ] **Formal Verification** - Formal proofs of security properties
- [ ] **Fuzzing** - Expand fuzzing coverage
- [ ] **Performance** - Optimize hot paths
- [ ] **Documentation** - Improve code docs and user guides

### Medium Priority

- [ ] **Mobile Apps** - React Native wrappers
- [ ] **Mesh Networking** - WiFi Direct, Bluetooth support
- [ ] **UI/UX** - Improve frontend experience
- [ ] **Accessibility** - WCAG compliance
- [ ] **Internationalization** - Multi-language support

### Low Priority

- [ ] **Themes** - Dark/light mode options
- [ ] **Animations** - Smooth transitions
- [ ] **Notifications** - Desktop notifications
- [ ] **Plugins** - Extension system

## Testing Requirements

All PRs must:

- [ ] Include tests for new functionality
- [ ] Pass `cargo test`
- [ ] Pass `cargo clippy --all-targets -- -D warnings`
- [ ] Pass `cargo fmt --check`

For crypto/security changes:

- [ ] Consider boundary cases for fuzzing
- [ ] Document security properties
- [ ] Add property-based tests where applicable

## Code Style

### Rust

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` (rustfmt)
- Use `cargo clippy` for lints
- Document public API with rustdoc

### TypeScript/React

- Follow [TypeScript Style Guide](https://google.github.io/styleguide/tsguide.html)
- Use ESLint and Prettier
- Document components with JSDoc

## Documentation

When adding new features:

1. **Code Comments** - Explain why, not what
2. **Rustdoc** - Document public API
3. **User Docs** - Update README or create new docs
4. **Examples** - Provide usage examples

## Questions?

- **General:** Create a [Discussion](https://github.com/shadowgram/shadowgram/discussions)
- **Bugs:** Create an [Issue](https://github.com/shadowgram/shadowgram/issues)
- **Security:** Email security@shadowgram.org

---

**NO BACKDOORS. NO COMPROMISES.**

Thank you for helping make Shadowgram better!