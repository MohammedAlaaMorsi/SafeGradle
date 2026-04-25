# SafeGradle

![Build](https://github.com/MohammedAlaaMorsi/SafeGradle/workflows/Build/badge.svg)
[![Version](https://img.shields.io/jetbrains/plugin/v/30319-safegradle.svg)](https://plugins.jetbrains.com/plugin/30319-safegradle)
[![Downloads](https://img.shields.io/jetbrains/plugin/d/30319-safegradle.svg)](https://plugins.jetbrains.com/plugin/30319-safegradle)



<!-- Plugin description -->
**SafeGradle** is a professional-grade security scanner for IntelliJ IDEA that protects your development environment from malicious Gradle build scripts. It identifies security risks like hidden network calls, shell execution, and credential leaks *before* they can compromise your system.

### 🛡️ Key Features
- **Semantic PSI Analysis**: High-precision scanning using IntelliJ's Program Structure Interface (PSI) to detect obfuscated or dynamically constructed malicious code in both Kotlin (`.kts`) and Groovy scripts.
- **Pre-opening Security**: Integrated "Open in SafeGradle" actions on the Welcome Screen and "Trust Project" dialogs allow you to audit open-source projects before fully loading them.
- **Software Composition Analysis (SCA)**: Automatically detects dependencies with known vulnerabilities (CVEs) to prevent supply chain attacks.
- **Team-Wide Configuration**: Share security policies across your team using a `.safegradle.yml` file in your project root.
- **Real-time Protection**: Editor annotations, gutter icons, and Alt+Enter quick-fixes provide immediate feedback as you edit build scripts.
- **Incremental Scanning**: Intelligent caching ensures scans are lightning-fast, only re-checking files when they change.

Keep your IDE secure and code with confidence.
<!-- Plugin description end -->

## Installation

- Using the IDE built-in plugin system:

  <kbd>Settings/Preferences</kbd> > <kbd>Plugins</kbd> > <kbd>Marketplace</kbd> > <kbd>Search for "SafeGradle"</kbd> >
  <kbd>Install</kbd>

- Using JetBrains Marketplace:

  Go to [JetBrains Marketplace](https://plugins.jetbrains.com/plugin/30316-safegradle) and install it by clicking the <kbd>Install to ...</kbd> button in case your IDE is running.

  You can also download the [latest release](https://plugins.jetbrains.com/plugin/30316-safegradle/versions) from JetBrains Marketplace and install it manually using
  <kbd>Settings/Preferences</kbd> > <kbd>Plugins</kbd> > <kbd>⚙️</kbd> > <kbd>Install plugin from disk...</kbd>

- Manually:

  Download the [latest release](https://github.com/MohammedAlaaMorsi/SafeGradle/releases/latest) and install it manually using
  <kbd>Settings/Preferences</kbd> > <kbd>Plugins</kbd> > <kbd>⚙️</kbd> > <kbd>Install plugin from disk...</kbd>


---
Plugin based on the [IntelliJ Platform Plugin Template][template].

[template]: https://github.com/JetBrains/intellij-platform-plugin-template
[docs:plugin-description]: https://plugins.jetbrains.com/docs/intellij/plugin-user-experience.html#plugin-description-and-presentation
