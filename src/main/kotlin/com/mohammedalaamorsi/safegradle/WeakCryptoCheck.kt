package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class WeakCryptoCheck : SecurityCheck {
    override val id = "weak_cryptography"
    override val name = "Weak Cryptography"
    override val description = "Detects use of deprecated or broken cryptographic algorithms in build scripts."

    private data class CryptoRule(val pattern: Pattern, val algorithm: String, val recommendation: String)

    private val rules = listOf(
        CryptoRule(
            Pattern.compile("""DESKeySpec|DESede|"DES"|'DES'|Cipher\.getInstance\("DES""", Pattern.CASE_INSENSITIVE),
            "DES",
            "DES has an effective key length of 56 bits and is broken. Use AES-256 instead."
        ),
        CryptoRule(
            Pattern.compile("""RC4|ARCFOUR|"RC4"|'RC4'""", Pattern.CASE_INSENSITIVE),
            "RC4",
            "RC4 is cryptographically broken. Use AES-GCM or ChaCha20-Poly1305 instead."
        ),
        CryptoRule(
            Pattern.compile("""MessageDigest\.getInstance\(["']MD5["']|new\s+MD5|\.md5\(\)|DigestUtils\.md5""", Pattern.CASE_INSENSITIVE),
            "MD5",
            "MD5 is broken for security purposes (collision attacks). Use SHA-256 or SHA-3 for security-sensitive hashing."
        ),
        CryptoRule(
            // SHA-1 only in a security context — not in a checksum/integrity context (those are handled by checksumKeywords)
            Pattern.compile("""MessageDigest\.getInstance\(["']SHA-1["']|MessageDigest\.getInstance\(["']SHA1["']""", Pattern.CASE_INSENSITIVE),
            "SHA-1",
            "SHA-1 is deprecated for security use (collision attacks since 2017). Use SHA-256 or SHA-3 instead."
        ),
        CryptoRule(
            Pattern.compile("""KeyFactory\.getInstance\(["']RSA["']\)|RSAPublicKeySpec.*512|RSAPrivateKeySpec.*512|RSAKeyGenParameterSpec\s*\(\s*512\b""", Pattern.CASE_INSENSITIVE),
            "RSA-512",
            "RSA keys under 2048 bits are considered broken. Use RSA-2048 or RSA-4096."
        )
    )

    // Lines that are clearly about file integrity checks — not security crypto
    private val checksumContext = setOf("checksum", "sha256sum", "distributionsha256sum", "hash", "fingerprint", "digest")

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("//") || stripped.startsWith("#")) return@forEachIndexed
            val lower = stripped.lowercase()
            if (checksumContext.any { lower.contains(it) }) return@forEachIndexed

            for (rule in rules) {
                if (rule.pattern.matcher(line).find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = stripped,
                            message = "Weak cryptography: ${rule.algorithm} detected. ${rule.recommendation}",
                            riskLevel = RiskLevel.HIGH,
                            checkId = id
                        )
                    )
                    break // one violation per line per check
                }
            }
        }
        return violations
    }
}
