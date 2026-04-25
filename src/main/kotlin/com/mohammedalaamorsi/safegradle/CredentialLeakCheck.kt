package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class CredentialLeakCheck : SecurityCheck {
    override val id = "credential_leak"
    override val name = "Credential Leak Detection"
    override val description = "Detects hardcoded API keys, tokens, and secrets in build scripts and properties files."

    private val patterns = listOf(
        Pattern.compile("(api[_-]?key|apikey)\\s*[=:]\\s*[\"'][^\"']+[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(password|passwd|secret|token)\\s*[=:]\\s*[\"'][^\"']+[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}"), // AWS key ID
        Pattern.compile("ghp_[0-9a-zA-Z]{36}"),  // GitHub PAT
        Pattern.compile("sk-[0-9a-zA-Z]{48}"),    // OpenAI key
        Pattern.compile("AIza[0-9A-Za-z_-]{35}"), // Google API key
        Pattern.compile("ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*") // JWT
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            // Skip comments
            if (line.trim().startsWith("//") || line.trim().startsWith("#")) {
                return@forEachIndexed
            }

            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Potential credential leak detected: ${matcher.group().substringBefore("=").substringBefore(":")}",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }
}
