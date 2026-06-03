package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class SensitiveFileCheck : SecurityCheck {
    override val id = "sensitive_file_access"
    override val name = "Sensitive File Access"
    override val description = "Detects attempts to access sensitive system files or credentials."

    private val patterns = listOf(
        Pattern.compile("System\\.getProperty\\([\"']user\\.home[\"']\\)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.ssh/|\\.aws/|\\.kube/|\\.gnupg/", Pattern.CASE_INSENSITIVE),
        Pattern.compile("id_rsa|id_dsa|id_ed25519", Pattern.CASE_INSENSITIVE),
        Pattern.compile("bash_history|zsh_history", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/etc/passwd|/etc/shadow", Pattern.CASE_INSENSITIVE),
        // Android signing keystore file references (accessing the actual file, not reading via LocalProperties API)
        Pattern.compile("\\.keystore|\\.jks|\\.p12|\\.pfx", Pattern.CASE_INSENSITIVE),
        Pattern.compile("keystore\\.properties", Pattern.CASE_INSENSITIVE)
    )

    // Android signing config patterns — flagged only when a hardcoded value is present
    private val signingPatterns = listOf(
        Pattern.compile("storePassword\\s*[=:]\\s*[\"']([^\"'\\$\\{][^\"']*)[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("keyPassword\\s*[=:]\\s*[\"']([^\"'\\$\\{][^\"']*)[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("keyAlias\\s*[=:]\\s*[\"']([^\"'\\$\\{][^\"']*)[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("storeFile\\s+file\\([\"']([^\"']+)[\"']\\)", Pattern.CASE_INSENSITIVE)
    )

    private val signingPlaceholders = setOf(
        "password", "changeit", "secret", "your-password", "your_password",
        "keypassword", "storepassword", "alias", "your-alias", "keystore.jks",
        "release.jks", "debug.jks", "release.keystore", "debug.keystore"
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("//") || stripped.startsWith("#")) return@forEachIndexed

            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = stripped,
                            message = "Access to sensitive file/property detected: ${matcher.group()}",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }

            for (pattern in signingPatterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    val value = if (matcher.groupCount() >= 1) matcher.group(1).lowercase().trim() else ""
                    if (value.isNotEmpty() && !signingPlaceholders.contains(value)) {
                        violations.add(
                            SecurityViolation(
                                file = file,
                                line = index + 1,
                                content = stripped,
                                message = "Hardcoded Android signing credential detected: '${matcher.group().substringBefore("(")}'. Use environment variables or keystore.properties (excluded from VCS) instead.",
                                riskLevel = RiskLevel.HIGH
                            )
                        )
                    }
                }
            }
        }
        return violations
    }
}
