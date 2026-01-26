package com.github.safegradle.security

import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class NetworkActivityCheck : SecurityCheck {
    override val id = "network_activity"
    override val name = "Suspicious Network Activity"
    override val description = "Detects attempts to make network connections."

    private val patterns = listOf(
        Pattern.compile("java\\.net\\.URL", Pattern.CASE_INSENSITIVE),
        Pattern.compile("HttpURLConnection", Pattern.CASE_INSENSITIVE),
        Pattern.compile("OkHttpClient", Pattern.CASE_INSENSITIVE),
        Pattern.compile("InetAddress", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Socket\\(", Pattern.CASE_INSENSITIVE),
        // Simple regex for IP addresses (excluding localhost 127.0.0.1)
        Pattern.compile("(http|https)://(?!localhost|127\\.0\\.0\\.1)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", Pattern.CASE_INSENSITIVE)
    )

    override fun check(file: VirtualFile, content: String): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            // Skip legitimate dependency declarations and plugin repositories
            if (line.trim().startsWith("maven") || 
                line.trim().startsWith("google()") || 
                line.trim().startsWith("jcenter()") ||
                line.trim().startsWith("classpath") ||
                line.trim().startsWith("implementation") ||
                line.trim().startsWith("api")) {
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
                            message = "Suspicious network activity detected: ${matcher.group()}",
                            riskLevel = RiskLevel.MEDIUM
                        )
                    )
                }
            }
        }
        return violations
    }
}
