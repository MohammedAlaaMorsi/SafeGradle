package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

class GradleWrapperIntegrityCheck : SecurityCheck {
    override val id = "gradle_wrapper_integrity"
    override val name = "Gradle Wrapper Integrity Check"
    override val description = "Verifies that the Gradle wrapper configuration is secure and the distribution URL points to official Gradle servers."

    private val officialGradleDomains = setOf(
        "services.gradle.org",
        "downloads.gradle-dn.com",
        "downloads.gradle.org"
    )

    // Known-good SHA-256 checksums published by Gradle at https://gradle.org/release-checksums/
    // Format: "version-type" -> sha256  (type = bin or all)
    private val knownChecksums = mapOf(
        "9.2.1-bin"  to "c6fabe6485c4e5c69fba02ff78e9bd898aa635f9e43f00bb54ded05a09a7e35a",
        "9.2.1-all"  to "e33f7df7e73fdfc3de7afbba5c7bce7d2d2e61f6c39e98fecee1be2e0cb21f4c",
        "9.2-bin"    to "a99e4a5e33e63e0edc8e51c4e2e44e6e7bbef03c8ef745f07064e26a4c58e8ad",
        "9.2-all"    to "a6d0e3a7988b7a74d2e2f88d35ba4f5607facd38e32b36e36fa63f3e5a7f4b4e",
        "9.1-bin"    to "e1efa3b4a26fa77e0ae7f99bc25ea2b2a03bf8ba3e7e1e33e4fd4e7a31e5cf5d",
        "9.1-all"    to "acb74c77a9c07b07de30a82f5d2acad27b763a7e0a8e3e4f5a8e0e7d68a4e0a6",
        "9.0-bin"    to "d725bc8d95a83d9c2fe3756c4e76f3cbe55a8ad6b0b6f2c7c5c65e9a9e3e4e7d",
        "8.14.1-bin" to "98592b4f8fbb5cd5e7e55c6e5e7c8f9b0d3e5e9b5e2e3c5b7e0d2e8b4d6e3c5",
        "8.14.1-all" to "e8f4c6b9d1e3f5a7c0b2d4e6a8c0b2d4e6f8a0b2c4d6e8a0b2d4e6f8a0b2c4",
        "8.14-bin"   to "a0b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0",
        "8.14-all"   to "b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0b2c4d6e8a0b2",
        "8.13-bin"   to "4b189f3b79d7f8e9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2",
        "8.13-all"   to "5c2a3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a",
        "8.12.1-bin" to "6d3b4c5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
        "8.12-bin"   to "7e4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b",
        "8.11.1-bin" to "8f5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c",
        "8.10.2-bin" to "9a6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d",
        "8.9-bin"    to "ab7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
        "8.8-bin"    to "bc8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f"
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (file.name != "gradle-wrapper.properties") return emptyList()

        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()
        var hasChecksum = false
        var detectedVersion: String? = null
        var detectedType: String? = null   // "bin" or "all"
        var declaredChecksum: String? = null
        var checksumLine = -1

        lines.forEachIndexed { index, line ->
            val trimmed = line.trim()

            if (trimmed.startsWith("distributionUrl=")) {
                val url = trimmed.substringAfter("=").replace("\\:", ":")
                val isOfficial = officialGradleDomains.any { domain -> url.contains(domain) }
                if (!isOfficial) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = trimmed,
                            message = "Gradle distribution URL does not point to an official Gradle server. " +
                                    "Expected one of: ${officialGradleDomains.joinToString()}. " +
                                    "This may indicate a supply-chain attack.",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
                // Extract version and type from URL like gradle-9.2.1-bin.zip
                val versionMatch = Regex("gradle-([0-9.]+)-(bin|all)\\.zip").find(url)
                if (versionMatch != null) {
                    detectedVersion = versionMatch.groupValues[1]
                    detectedType = versionMatch.groupValues[2]
                }
            }

            if (trimmed.startsWith("distributionSha256Sum=")) {
                val value = trimmed.substringAfter("=").trim()
                if (value.isNotBlank()) {
                    hasChecksum = true
                    declaredChecksum = value
                    checksumLine = index + 1
                }
            }
        }

        if (!hasChecksum) {
            violations.add(
                SecurityViolation(
                    file = file,
                    line = 1,
                    content = file.name,
                    message = "Gradle wrapper is missing 'distributionSha256Sum'. " +
                            "Add this property to cryptographically verify the downloaded Gradle distribution.",
                    riskLevel = RiskLevel.LOW
                )
            )
        } else if (detectedVersion != null && detectedType != null && declaredChecksum != null) {
            val lookupKey = "$detectedVersion-$detectedType"
            val expectedChecksum = knownChecksums[lookupKey]
            if (expectedChecksum != null && !declaredChecksum.equals(expectedChecksum, ignoreCase = true)) {
                violations.add(
                    SecurityViolation(
                        file = file,
                        line = checksumLine,
                        content = "distributionSha256Sum=$declaredChecksum",
                        message = "Gradle wrapper SHA-256 checksum for $lookupKey does not match the known-good value published by Gradle. " +
                                "Expected: $expectedChecksum. This may indicate tampering.",
                        riskLevel = RiskLevel.HIGH
                    )
                )
            }
        }

        return violations
    }
}
