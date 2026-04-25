package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class ObfuscationCheck : SecurityCheck {
    override val id = "obfuscated_code"
    override val name = "Obfuscated Code Detection"
    override val description = "Detects attempts to hide malicious payloads using Base64 encoding or dynamic reflection."

    private val patterns = listOf(
        // Base64 manipulation classes
        Pattern.compile("java\\.util\\.Base64", Pattern.CASE_INSENSITIVE),
        Pattern.compile("android\\.util\\.Base64", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.decodeBase64\\(", Pattern.CASE_INSENSITIVE),
        
        // Very long Base64 string likelihood (at least 40 Base64 characters)
        // This regex looks for strings that look like base64 payloads
        Pattern.compile("[\"'][A-Za-z0-9+/]{40,}={0,2}[\"']", Pattern.CASE_INSENSITIVE),
        
        // Java Reflection (often used to dynamically load concealed code)
        Pattern.compile("java\\.lang\\.reflect", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.getDeclaredMethod\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.invoke\\(", Pattern.CASE_INSENSITIVE),
        
        // Hex encoded arrays or heavy byte manipulation
        Pattern.compile("[\"']\\\\x[0-9a-fA-F]{2}", Pattern.CASE_INSENSITIVE)
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            // Skip legitimate build declarations that might contain "invoke" or look weird
            if (line.trim().startsWith("plugins") || 
                line.trim().startsWith("id(") ||
                line.trim().startsWith("//")) {
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
                            message = "Potential code obfuscation or dynamic loading detected: ${matcher.group()}",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }
}
