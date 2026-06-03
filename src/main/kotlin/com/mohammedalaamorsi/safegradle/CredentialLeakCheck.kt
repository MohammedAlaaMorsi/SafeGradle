package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class CredentialLeakCheck : SecurityCheck {
    override val id = "credential_leak"
    override val name = "Credential Leak Detection"
    override val description = "Detects hardcoded API keys, tokens, and secrets in build scripts and properties files."

    // Generic key=value patterns — subject to placeholder filtering before reporting
    private val genericPatterns = listOf(
        Pattern.compile("(api[_-]?key|apikey)\\s*[=:]\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("(password|passwd|secret|token)\\s*[=:]\\s*[\"']([^\"']+)[\"']", Pattern.CASE_INSENSITIVE)
    )

    // Gradle Enterprise / Develocity access keys — grant access to build scan data and remote cache
    private val gradleEnterprisePatterns = listOf(
        Pattern.compile("gradle\\.enterprise\\.accessKey\\s*=\\s*(\\S+)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("develocity\\.accessKey\\s*=\\s*(\\S+)", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ge\\.accessKey\\s*=\\s*(\\S+)", Pattern.CASE_INSENSITIVE)
    )

    // High-confidence patterns with recognisable prefixes — no placeholder filtering needed
    private val specificPatterns = listOf(
        Pattern.compile("(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[0-9A-Z]{16}"),  // AWS key ID
        Pattern.compile("ghp_[0-9a-zA-Z]{36}"),                                      // GitHub PAT
        Pattern.compile("ghs_[0-9a-zA-Z]{36}"),                                      // GitHub server-to-server token
        Pattern.compile("sk-[0-9a-zA-Z]{48}"),                                       // OpenAI secret key
        Pattern.compile("AIza[0-9A-Za-z_-]{35}"),                                    // Google API key
        Pattern.compile("ey[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_.+/=]+") // JWT (all three parts)
    )

    // Known placeholder / documentation values that should not be flagged
    private val placeholderValues = setOf(
        "changeit", "password", "secret", "token", "apikey", "api_key", "api-key",
        "your-password", "your_password", "yourpassword",
        "your-secret", "your_secret", "yoursecret",
        "your-token", "your_token", "yourtoken",
        "your-api-key", "yourapikey",
        "demo", "test", "testing", "example", "sample", "placeholder",
        "change-me", "change_me", "changeme",
        "replace-me", "replace_me", "replaceme",
        "fill-in", "fill_in", "fillin",
        "enter-here", "enter_here",
        "todo", "fixme", "tbd",
        "null", "none", "empty", "blank",
        "pass", "pass123", "password123", "letmein", "admin", "admin123",
        "mypassword", "mytoken", "mysecret",
        "test123", "test1234", "testpass"
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            if (line.trim().startsWith("//") || line.trim().startsWith("#")) return@forEachIndexed

            // Generic patterns: apply placeholder and quality filters
            for (pattern in genericPatterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    val value = matcher.group(2) ?: continue
                    if (isPlaceholder(value)) continue

                    val keyName = matcher.group(1)
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Potential credential leak: '$keyName' has a hardcoded value. Use environment variables or a secrets manager instead.",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }

            // Gradle Enterprise / Develocity access key
            for (pattern in gradleEnterprisePatterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    val value = if (matcher.groupCount() >= 1) matcher.group(1) else ""
                    if (value.isNotBlank() && !isPlaceholder(value)) {
                        violations.add(
                            SecurityViolation(
                                file = file,
                                line = index + 1,
                                content = line.trim(),
                                message = "Gradle Enterprise / Develocity access key detected. This grants access to build scan data and the remote build cache — store it in an environment variable instead.",
                                riskLevel = RiskLevel.HIGH
                            )
                        )
                    }
                }
            }

            // Specific patterns: report directly, no filtering needed
            for (pattern in specificPatterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Hardcoded credential detected: ${matcher.group().take(12)}… (matches known secret format).",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }

    private fun isPlaceholder(value: String): Boolean {
        val lower = value.lowercase().trim()
        // Too short to be a real credential
        if (lower.length < 8) return true
        // Known placeholder literal
        if (placeholderValues.contains(lower)) return true
        // ALL_CAPS_CONSTANT  — likely a symbolic name, not a secret
        if (value == value.uppercase() && value.all { it.isLetterOrDigit() || it == '_' || it == '-' }) return true
        // Starts with placeholder-indicating words
        if (lower.startsWith("your") || lower.startsWith("enter") || lower.startsWith("insert")) return true
        // Ends with placeholder-indicating suffixes
        if (lower.endsWith("-here") || lower.endsWith("_here") || lower.endsWith("-placeholder") ||
            lower.endsWith("_placeholder") || lower.endsWith("-example") || lower.endsWith("_example")) return true
        // Contains spaces — descriptive text, not a secret
        if (value.contains(" ")) return true
        return false
    }
}
