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

        // Long Base64-encoded payloads: 60+ chars, must contain Base64-specific chars (+ / =)
        // Pure hex strings (SHA checksums) are excluded by the post-match filter below.
        Pattern.compile("[\"'][A-Za-z0-9+/]{60,}={0,2}[\"']"),

        // Java Reflection — rarely needed in legitimate build scripts
        Pattern.compile("java\\.lang\\.reflect", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.getDeclaredMethod\\(", Pattern.CASE_INSENSITIVE),

        // Hex-encoded byte arrays
        Pattern.compile("[\"']\\\\x[0-9a-fA-F]{2}", Pattern.CASE_INSENSITIVE)
    )

    // Keywords that indicate the line contains a legitimate hash/checksum, not obfuscated code
    private val checksumKeywords = setOf("sha256", "sha1", "sha512", "md5", "checksum", "hash", "fingerprint", "digest", "distributionsha256sum")

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            val stripped = line.trim()
            // Skip comments and plugin declarations
            if (stripped.startsWith("//") || stripped.startsWith("#") ||
                stripped.startsWith("plugins") || stripped.startsWith("id(")) {
                return@forEachIndexed
            }

            // Skip lines that are clearly about checksums / hashes
            val lineLower = stripped.lowercase()
            if (checksumKeywords.any { lineLower.contains(it) }) return@forEachIndexed

            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    val match = matcher.group()

                    // For the long-string pattern: skip pure hex strings (SHA-256/SHA-1/MD5 checksums)
                    if (match.length > 2) {
                        val inner = match.trimStart('"', '\'').trimEnd('"', '\'', '=')
                        if (inner.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) continue
                    }

                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = stripped,
                            message = "Potential code obfuscation or dynamic loading detected: $match",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }
}
