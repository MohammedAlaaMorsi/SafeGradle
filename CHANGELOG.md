# Changelog

## [Unreleased]

## [0.0.32]
### 🛡️ Smarter Detection
- **Catch hidden threats**: SafeGradle now understands the actual structure of your Kotlin and Groovy code, so obfuscated or split-up malicious URLs can no longer hide in string templates.
- **Vulnerable dependency alerts**: Get warned when your project uses a library version with known security vulnerabilities (CVEs), like Log4j or outdated Guava releases.
- **Typosquatting protection**: Detects when a dependency name looks suspiciously similar to a popular library — a common supply chain attack vector.
- **Credential leak detection**: Flags hardcoded API keys, passwords, and tokens accidentally left in your build scripts.
- **File exfiltration checks**: Identifies Gradle tasks that attempt to read or upload sensitive files from your system.

### ⚡ Faster & Smoother
- **Instant re-scans**: Once a file has been scanned, it's cached. Only modified files are re-checked, making repeated scans nearly instant.
- **Auto-scan on project open**: Your project is automatically scanned in the background the moment you open it — no manual action needed.
- **Full Kotlin K2 mode support**: Fully compatible with IntelliJ IDEA 2025.1's default K2 analysis engine.

### 🎯 One-Click Fixes
- **Ignore with Alt+Enter**: Hover over any warning and press Alt+Enter to suppress it with a single click.
- **Whitelist trusted domains**: Quickly add a flagged URL's domain to your project whitelist — no more false positives on your own servers.

### 👥 Team Collaboration
- **Shared security policies**: Drop a `.safegradle.yml` file in your project root to define whitelisted domains and suppressed rules for your entire team.
- **Export security reports**: One-click CSV export of all findings to share with your security team or include in code reviews.

### 🔍 Security Dashboard
- **Dedicated tool window**: A persistent "SafeGradle" panel at the bottom of your IDE shows all findings with risk levels (🔴 High, 🟠 Medium, 🔵 Low).
- **Click-to-navigate**: Double-click any finding to jump directly to the exact line in your code.
- **Global init-script scanning**: SafeGradle now also checks your system-wide `~/.gradle/init.d/` scripts for persistence malware.
- **Gradle wrapper verification**: Automatically validates the SHA-256 checksum of `gradle-wrapper.jar` to detect tampering.

## [0.0.1]
### Added
- Initial release of SafeGradle security scanner.
- Integration with IntelliJ Safe Mode (untrusted projects).
- Detection of shell execution, network activity, and sensitive file access in Gradle scripts.
