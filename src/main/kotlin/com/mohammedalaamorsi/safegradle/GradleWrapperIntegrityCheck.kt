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

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (file.name != "gradle-wrapper.properties") return emptyList()

        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()
        var hasChecksum = false

        lines.forEachIndexed { index, line ->
            val trimmed = line.trim()

            if (trimmed.startsWith("distributionUrl=")) {
                // Unescape backslash-colon used in .properties files (e.g. https\://...)
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
            }

            if (trimmed.startsWith("distributionSha256Sum=") && trimmed.substringAfter("=").isNotBlank()) {
                hasChecksum = true
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
        }

        return violations
    }
}
