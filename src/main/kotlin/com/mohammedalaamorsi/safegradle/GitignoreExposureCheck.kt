package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

class GitignoreExposureCheck : SecurityCheck {
    override val id = "gitignore_exposure"
    override val name = "Sensitive File Exposure via VCS"
    override val description = "Warns when sensitive files (keystores, signing configs, service keys) are not excluded from version control."

    // Files/patterns that MUST appear in .gitignore
    private val sensitivePatterns = listOf(
        "*.jks", "*.keystore", "*.p12", "*.pfx",
        "keystore.properties",
        "local.properties",
        "google-services.json",
        "GoogleService-Info.plist",
        "*.aab",          // signed app bundles
        ".env",
        "secrets.properties",
        "signing.properties"
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (file.name != ".gitignore") return emptyList()

        val violations = mutableListOf<SecurityViolation>()
        val gitignoreEntries = content.lines()
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.startsWith("#") }
            .toSet()

        for (pattern in sensitivePatterns) {
            if (!isCovered(pattern, gitignoreEntries)) {
                violations.add(
                    SecurityViolation(
                        file = file,
                        line = content.lines().size, // report at end of file
                        content = "(missing entry)",
                        message = "'$pattern' is not excluded in .gitignore — if this file is committed, credentials or signing keys could be leaked to the repository.",
                        riskLevel = RiskLevel.HIGH
                    )
                )
            }
        }
        return violations
    }

    private fun isCovered(pattern: String, entries: Set<String>): Boolean {
        if (entries.contains(pattern)) return true
        // Accept parent-dir wildcards like **/local.properties or /local.properties
        val base = pattern.trimStart('*', '/', '.')
        return entries.any { entry ->
            val normalised = entry.trimStart('*', '/', '.')
            normalised == base || normalised.endsWith("/$base") || normalised == pattern.trimStart('/')
        }
    }
}
