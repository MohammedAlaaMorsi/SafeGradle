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

    companion object {
        // Official SHA-256 checksums from https://services.gradle.org/distributions/gradle-<version>-<type>.zip.sha256
        // Key: "version-type" (type = bin or all)
        private val knownChecksums = mapOf(
            "9.2.1-bin"  to "72f44c9f8ebcb1af43838f45ee5c4aa9c5444898b3468ab3f4af7b6076c5bc3f",
            "9.2.1-all"  to "f86344275d1b194688dd330abf9f6f2344cd02872ffee035f2d1ea2fd60cf7f3",
            "9.2.0-bin"  to "df67a32e86e3276d011735facb1535f64d0d88df84fa87521e90becc2d735444",
            "9.2.0-all"  to "16f2b95838c1ddcf7242b1c39e7bbbb43c842f1f1a1a0dc4959b6d4d68abcac3",
            "9.1.0-bin"  to "a17ddd85a26b6a7f5ddb71ff8b05fc5104c0202c6e64782429790c933686c806",
            "9.1.0-all"  to "b84e04fa845fecba48551f425957641074fcc00a88a84d2aae5808743b35fc85",
            "9.0.0-bin"  to "8fad3d78296ca518113f3d29016617c7f9367dc005f932bd9d93bf45ba46072b",
            "9.0.0-all"  to "f759b8dd5204e2e3fa4ca3e73f452f087153cf81bac9561eeb854229cc2c5365",
            "8.14.1-bin" to "845952a9d6afa783db70bb3b0effaae45ae5542ca2bb7929619e8af49cb634cf",
            "8.14.1-all" to "d7042b3c11565c192041fc8c4703f541b888286404b4f267138c1d094d8ecdca",
            "8.14-bin"   to "61ad310d3c7d3e5da131b76bbf22b5a4c0786e9d892dae8c1658d4b484de3caa",
            "8.14-all"   to "efe9a3d147d948d7528a9887fa35abcf24ca1a43ad06439996490f77569b02d1",
            "8.13-bin"   to "20f1b1176237254a6fc204d8434196fa11a4cfb387567519c61556e8710aed78",
            "8.13-all"   to "fba8464465835e74f7270bbf43d6d8a8d7709ab0a43ce1aa3323f73e9aa0c612",
            "8.12.1-bin" to "8d97a97984f6cbd2b85fe4c60a743440a347544bf18818048e611f5288d46c94",
            "8.12-bin"   to "7a00d51fb93147819aab76024feece20b6b84e420694101f276be952e08bef03",
            "8.11.1-bin" to "f397b287023acdba1e9f6fc5ea72d22dd63669d59ed4a289a29b1a76eee151c6",
            "8.10.2-bin" to "31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26",
            "8.9-bin"    to "d725d707bfabd4dfdc958c624003b3c80accc03f7037b5122c4b1d0ef15cecab",
            "8.8-bin"    to "a4b4158601f8636cdeeab09bd76afb640030bb5b144aafe261a5e8af027dc612"
        )

        fun lookupExpectedChecksum(version: String, type: String): String? = knownChecksums["$version-$type"]
    }

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
                    riskLevel = RiskLevel.LOW,
                    fixVersion = if (detectedVersion != null && detectedType != null) lookupExpectedChecksum(detectedVersion!!, detectedType!!) else null
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
                        riskLevel = RiskLevel.HIGH,
                        fixVersion = expectedChecksum
                    )
                )
            }
        }

        return violations
    }
}
