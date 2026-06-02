# Changelog

## [Unreleased]

## [0.0.35]

### 🛡️ 17 New Security Checks

- **Remote script inclusion** (`apply from: URL`): Detects `apply from: 'https://...'` which downloads and executes arbitrary Groovy/Kotlin at build-configuration time — before any task runs. Whitelistable per-team via `allowed_script_sources` in `.safegradle.yml`.
- **Dependency downgrade via `resolutionStrategy.force`**: Flags `force('group:artifact:version')` calls that silently pin a transitive dependency to a vulnerable version. Automatically cross-referenced against the CVE database.
- **Dangerous JVM daemon flags**: Detects `-javaagent:`, `-agentlib:`, `-agentpath:`, `-Xbootclasspath`, and `--add-opens` in `org.gradle.jvmargs` inside `gradle.properties` — flags that modify the Gradle daemon process itself.
- **Maven/Ivy version range syntax**: Detects open ranges like `(1.0,2.0)` or `[1.0,)` that resolve to a different artifact on every build, enabling silent version substitution attacks.
- **Hardcoded IP-address URLs**: Flags `http(s)://x.x.x.x/` URLs that bypass all domain-based whitelisting. Public IPs only — private ranges (RFC 1918, loopback, link-local) are excluded.
- **Gradle Enterprise / Develocity access keys**: Detects hardcoded `gradle.enterprise.accessKey` and `develocity.accessKey` values that grant access to build scan data and remote build caches.
- **Crypto-mining pool and C2 indicators**: Detects Stratum protocol strings, known mining pool hostnames, and DNS out-of-band exfiltration services (dnslog.cn, ceye.io, etc.).
- **Git hook tampering**: Flags references to `.git/hooks/` paths — writing to this directory installs persistent code that survives the build and executes on every future git operation.
- **`libs.versions.toml` CVE scanning**: Version catalog files are now parsed natively (inline and table-style `{ module = "…", version = "…" }` entries), feeding both the offline CVE database and the live OSV.dev lookup.
- **Android signing credential detection**: Detects hardcoded `storePassword`, `keyPassword`, and `keyAlias` values in `signingConfigs` blocks and `.keystore`/`.jks`/`.p12` file references.
- **JCenter deprecation warning**: `jcenter()` references now emit a `LOW` advisory — JCenter was shut down in February 2022. Migrate to Maven Central.
- **Insecure HTTP repository URLs**: Plain `http://` (non-HTTPS) repository URLs are flagged `HIGH` as active MITM attack vectors.
- **Weak cryptography**: Detects DES, RC4, MD5 (in security context), SHA-1, and RSA keys under 2048 bits with clear remediation guidance.
- **String interpolation in `commandLine`**: Detects `commandLine(..."${var}"...)` patterns where project-property interpolation can be weaponised as a command injection vector.
- **Dependency lock file absence**: Warns (LOW) when no `dependencyLocking {}` configuration or `gradle/dependency-locks/` directory exists, leaving transitive resolution non-deterministic.
- **`.gitignore` exposure audit**: Checks that `.jks`, `*.keystore`, `keystore.properties`, `google-services.json`, `.env`, and other credential-bearing files are excluded from version control.
- **`buildSrc` and composite build scanning**: `buildSrc/` and any `includeBuild()` directories are now fully scanned — they contain arbitrary Kotlin/Groovy code that runs before the main build with unrestricted access.

### ⚡ Performance & Architecture

- **Parallel file scanning**: Files no longer scanned sequentially — a bounded thread pool (sized to CPU core count) scans uncached files concurrently. Large monorepos see significant speed improvements.
- **Scan on save**: Build files are automatically re-scanned when saved. A `BulkFileListener` watches for `VFileContentChangeEvent` on all Gradle-related files and invalidates the cache entry before triggering a background rescan.
- **OSV.dev live CVE integration**: Dependencies are now batched and sent to `api.osv.dev/v1/querybatch` for real-time advisory lookups. The static CVE list remains as an instant offline fallback. Toggle in **Settings → SafeGradle Security**.

### 🎯 New Quick-Fix Intentions

- **Replace `http://` → `https://`** (Alt+Enter): One-click fix for insecure repository URLs on the current line.
- **Pin dynamic version** (Alt+Enter): Replaces `+`, `latest.release`, or `-SNAPSHOT` with a `TODO_PIN_VERSION` placeholder that triggers a compiler warning until pinned.

### 🎨 Tool Window Enhancements

- **Filter bar**: Search field and `🔴 HIGH` / `🟠 MED` / `🔵 LOW` toggle buttons for instant result filtering without leaving the panel.
- **"Explain this violation" detail panel**: Click any row to see the full message, affected code, and file location in a split panel below the table.
- **Violation grouping**: Toggle between grouping by file (default) and grouping by check type to triage all findings of the same category at once.
- **Scan history trend line**: Header now shows the last 5 scan totals as `🔴12 → 🔴8 → 🟠5 → 🔵3` so you can see whether your project is getting more or less secure over time.
- **Baseline mode**: "Save Baseline" saves the current findings as `.safegradle-baseline.json`. Enable "New Only" to show only findings that appeared after the baseline was created — ideal for adopting SafeGradle on existing codebases.
- **Export format chooser**: The export dialog now offers **CSV**, **JSON**, and **SARIF** (GitHub Code Scanning compatible) formats.

### 📊 Status Bar Widget

A persistent `SafeGradle 🔴3 🟠1` counter in the IDE status bar stays visible even when the tool window is closed. Click it to open the SafeGradle panel.

### 👥 Team & CI/CD Features

- **Per-check severity overrides**: Teams can promote or mute any check in `.safegradle.yml`:
  ```yaml
  severity_overrides:
    plugin_injection: none      # mute entirely
    shell_execution: HIGH       # promote to HIGH
  ```
- **`allowed_script_sources`**: Whitelist specific URL prefixes for `apply from:` statements:
  ```yaml
  allowed_script_sources:
    - https://raw.githubusercontent.com/myorg/
  ```
- **Generate GitHub Actions CI workflow**: *Tools → Generate SafeGradle CI Workflow* creates `.github/workflows/safegradle.yml` with a build → test → Plugin Verifier → SARIF upload pipeline.
- **SARIF export for GitHub Code Scanning**: Export findings in SARIF 2.1.0 format and upload to GitHub Code Scanning — findings appear as inline annotations on pull requests.
- **`.safegradle.yml` IDE autocomplete**: The config file now has a registered JSON Schema, providing autocomplete for check IDs, risk levels, and suppression fields in IntelliJ IDEA.

### 🔧 IntelliJ Platform Compatibility

- **Replaced `@UnstableApiUsage` `isTrusted()`** with the stable `TrustedProjects.isProjectTrusted()` API (stable since IntelliJ 2023.1).
- **Replaced `SwingUtilities.invokeLater`** with `ApplicationManager.getApplication().invokeLater()` throughout for correct IntelliJ threading model compliance.
- **Removed dead JCenter/Bintray domains** from the built-in whitelist — both services were shut down in 2022.
- Minimum supported version remains **IntelliJ IDEA 2025.1** (build 251).

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
