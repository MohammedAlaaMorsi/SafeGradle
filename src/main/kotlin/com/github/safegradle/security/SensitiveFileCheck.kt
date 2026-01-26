package com.github.safegradle.security

import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class SensitiveFileCheck : SecurityCheck {
    override val id = "sensitive_file_access"
    override val name = "Sensitive File Access"
    override val description = "Detects attempts to access sensitive system files or credentials."

    private val patterns = listOf(
        Pattern.compile("System\\.getProperty\\([\"']user\\.home[\"']\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("System\\.getenv\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.ssh/|\\.aws/|\\.kube/|\\.gnupg/", Pattern.CASE_INSENSITIVE),
        Pattern.compile("id_rsa|id_dsa|id_ed25519", Pattern.CASE_INSENSITIVE),
        Pattern.compile("bash_history|zsh_history", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/etc/passwd|/etc/shadow", Pattern.CASE_INSENSITIVE),
        Pattern.compile("local\\.properties", Pattern.CASE_INSENSITIVE) // Accessing local.properties programmatically can be sus
    )

    override fun check(file: VirtualFile, content: String): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Access to sensitive file/property detected: ${matcher.group()}",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }
}
