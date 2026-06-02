package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class ApplyFromCheck : SecurityCheck {
    override val id = "apply_from_remote"
    override val name = "Remote Script Inclusion"
    override val description = "Detects apply from: with a remote URL. Remote scripts execute arbitrary Groovy/Kotlin at build-configuration time, before any task runs."

    // Matches: apply from: 'https://...', apply from: "http://...", apply(from = "https://...")
    private val applyFromPattern = Pattern.compile(
        """apply\s*(?:from\s*[=:]\s*|[\(\{]\s*from\s*[=:]\s*)['"](https?://[^'"]+)['"]""",
        Pattern.CASE_INSENSITIVE
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()
        val allowedSources = teamConfig?.allowedScriptSources ?: emptyList()

        lines.forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("//") || stripped.startsWith("#")) return@forEachIndexed

            val matcher = applyFromPattern.matcher(line)
            while (matcher.find()) {
                val url = matcher.group(1)
                val isAllowed = allowedSources.any { url.startsWith(it) }
                if (isAllowed) continue

                violations.add(
                    SecurityViolation(
                        file = file,
                        line = index + 1,
                        content = stripped,
                        message = "Remote script inclusion: 'apply from: $url' downloads and executes arbitrary code at build-configuration time. Use a local file or a versioned plugin instead.",
                        riskLevel = RiskLevel.HIGH,
                        checkId = id
                    )
                )
            }
        }
        return violations
    }
}
