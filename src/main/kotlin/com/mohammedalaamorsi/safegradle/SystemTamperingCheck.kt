package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class SystemTamperingCheck : SecurityCheck {
    override val id = "system_tampering"
    override val name = "System Tampering Check"
    override val description = "Detects attempts to bypass SSL, alter SecurityManagers, or manipulate ClassLoaders."

    private val patterns = listOf(
        // SSL/TLS Bypassing (Trusting all certs)
        Pattern.compile("TrustManager", Pattern.CASE_INSENSITIVE),
        Pattern.compile("X509TrustManager", Pattern.CASE_INSENSITIVE),
        Pattern.compile("setHostnameVerifier", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SSLContext\\.getInstance", Pattern.CASE_INSENSITIVE),

        // ClassLoader manipulation
        Pattern.compile("URLClassLoader", Pattern.CASE_INSENSITIVE),
        Pattern.compile("defineClass\\(", Pattern.CASE_INSENSITIVE),

        // Security Manager manipulation
        Pattern.compile("System\\.setSecurityManager", Pattern.CASE_INSENSITIVE),
        Pattern.compile("SecurityManager", Pattern.CASE_INSENSITIVE),

        // Thread and System shutdown hooks often used by malware
        Pattern.compile("Runtime\\.getRuntime\\(\\)\\.addShutdownHook", Pattern.CASE_INSENSITIVE)
    )

    override fun check(file: VirtualFile, content: String): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            // Skip comments
            if (line.trim().startsWith("//")) {
                return@forEachIndexed
            }

            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    // Risk level is HIGH because standard build scripts rarely need to bypass SSL or mess with ClassLoaders
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Potential system tampering or SSL bypass detected: ${matcher.group()}",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }
}
