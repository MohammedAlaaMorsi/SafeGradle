# SafeGradle

![Build](https://github.com/MohammedAlaaMorsi/SafeGradle/workflows/Build/badge.svg)
[![Version](https://img.shields.io/jetbrains/plugin/v/30319-safegradle.svg)](https://plugins.jetbrains.com/plugin/30319-safegradle)
[![Downloads](https://img.shields.io/jetbrains/plugin/d/30319-safegradle.svg)](https://plugins.jetbrains.com/plugin/30319-safegradle)



<!-- Plugin description -->
**SafeGradle** is an IntelliJ Platform plugin designed to enhance your security by scanning project build scripts for malicious code *before* you open them.

### Features
- **Pre-opening Scanning**: Easily open projects with SafeGradle from the native "Trust Project" dialog or the Welcome Screen to scan projects for vulnerabilities before loading them.
- **Manual Actions**: Scan build scripts (like `build.gradle.kts`) within your currently opened project and display immediate notifications for any detected security risks.
- **Secure Workflow**: Adds an essential layer of safety when exploring unverified or open-source repositories to ensure that the code you trust is safe.

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
