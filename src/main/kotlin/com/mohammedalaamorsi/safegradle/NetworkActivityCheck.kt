package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiLiteralValue
import com.intellij.psi.PsiRecursiveElementVisitor
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
        // URL pattern (excluding localhost / 127.0.0.1)
        Pattern.compile("(http|https)://(?!localhost|127\\.0\\.0\\.1)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", Pattern.CASE_INSENSITIVE)
    )

    // Detects plain http:// (not https://) inside repository/maven/url blocks — MITM risk
    private val httpRepoPattern = Pattern.compile("http://(?!localhost|127\\.0\\.0\\.1)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", Pattern.CASE_INSENSITIVE)

    // Detects IP-address URLs — bypasses domain-based whitelisting entirely
    private val ipUrlPattern = Pattern.compile(
        """https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/[^\s'"]*)?""",
        Pattern.CASE_INSENSITIVE
    )
    // Private / link-local IP ranges that are clearly non-public (safe to skip)
    private val privateIpPattern = Pattern.compile(
        """https?://(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|127\.\d+\.\d+\.\d+|169\.254\.\d+\.\d+)""",
        Pattern.CASE_INSENSITIVE
    )

    // Crypto mining pool indicators and DNS-based C2 exfiltration patterns
    private val miningPatterns = listOf(
        Pattern.compile("stratum\\+tcp://", Pattern.CASE_INSENSITIVE),
        Pattern.compile("pool\\.minergate\\.com|xmrpool\\.eu|nanopool\\.org|f2pool\\.com|antpool\\.com|nicehash\\.com|miningpoolhub\\.com", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\bmonero\\b.*\\bwallet\\b|\\bxmr\\b.*\\bmine\\b|\\bmine.*\\bprofit\\b", Pattern.CASE_INSENSITIVE),
        // DNS-based C2 / OOB detection services used in exploit PoCs
        Pattern.compile("\\.dnslog\\.cn|\\.ceye\\.io|\\.requestbin\\.com|\\.interactsh\\.com|\\.burpcollaborator\\.net", Pattern.CASE_INSENSITIVE)
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()
        var braceDepth = 0
        var insideSafeBlock = false

        lines.forEachIndexed { index, line ->
            val strippedLine = SecurityUtils.stripComments(line).trim()
            if (strippedLine.isEmpty()) return@forEachIndexed

            // Track brace depth to identify blocks
            if (strippedLine.contains("{")) {
                if (SecurityUtils.isLikelySafeBlock(strippedLine)) {
                    insideSafeBlock = true
                }
                braceDepth += strippedLine.count { it == '{' }
            }
            
            val currentInsideSafeBlock = insideSafeBlock

            if (strippedLine.contains("}")) {
                braceDepth -= strippedLine.count { it == '}' }
                if (braceDepth <= 0) {
                    braceDepth = 0
                    insideSafeBlock = false
                }
            }

            // JCenter was shut down on 2022-02-01 — flag its use as a warning
            if (strippedLine.startsWith("jcenter()")) {
                violations.add(
                    SecurityViolation(
                        file = file,
                        line = index + 1,
                        content = strippedLine,
                        message = "JCenter (jcenter.bintray.com) was shut down in February 2022. Remove jcenter() and migrate to Maven Central or another active repository.",
                        riskLevel = RiskLevel.LOW
                    )
                )
                return@forEachIndexed
            }

            // Skip legitimate dependency declarations and plugin repositories or safe blocks
            if (currentInsideSafeBlock ||
                strippedLine.startsWith("google()") ||
                strippedLine.startsWith("classpath") ||
                strippedLine.startsWith("implementation") ||
                strippedLine.startsWith("api")) {
                return@forEachIndexed
            }

            val uncommented = SecurityUtils.stripComments(line)
            for (pattern in patterns) {
                val matcher = pattern.matcher(uncommented)
                while (matcher.find()) {
                    val match = matcher.group()

                    // Check if the match is a URL and if it's whitelisted
                    if (match.startsWith("http", ignoreCase = true) && WhitelistConfig.isWhitelistedUrl(match, project, teamConfig)) {
                        continue
                    }

                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Suspicious network activity detected: $match",
                            riskLevel = RiskLevel.MEDIUM
                        )
                    )
                }
            }

            // Crypto mining pool and DNS C2 detection (always HIGH — no legitimate use in build scripts)
            for (miningPattern in miningPatterns) {
                val m = miningPattern.matcher(uncommented)
                if (m.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Crypto-mining or command-and-control indicator detected: '${m.group().take(60)}'. This pattern has no legitimate use in a build script.",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }

            // Flag public IP-based URLs — they bypass all domain whitelisting
            val ipMatcher = ipUrlPattern.matcher(uncommented)
            while (ipMatcher.find()) {
                val url = ipMatcher.group()
                if (!privateIpPattern.matcher(url).find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "IP-address URL '$url' bypasses domain-based whitelisting. Use a hostname instead, or explicitly whitelist this endpoint in .safegradle.yml.",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }

            // Flag plain http:// (non-HTTPS) URLs anywhere in the file — susceptible to MITM attacks
            val httpMatcher = httpRepoPattern.matcher(uncommented)
            while (httpMatcher.find()) {
                val url = httpMatcher.group()
                if (!WhitelistConfig.isWhitelistedUrl(url, project, teamConfig)) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Insecure HTTP URL '$url' — use HTTPS to prevent man-in-the-middle attacks on dependency downloads.",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }

    override fun checkPsi(psiFile: PsiFile, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val document = psiFile.viewProvider.document ?: return emptyList()

        psiFile.accept(object : PsiRecursiveElementVisitor() {
            override fun visitElement(element: PsiElement) {
                super.visitElement(element)

                // Use platform-generic API (compatible with both K1 and K2 mode)
                val text = extractStringLiteral(element) ?: return

                val matcher = urlPattern.matcher(text)
                while (matcher.find()) {
                    val url = matcher.group()
                    if (!WhitelistConfig.isWhitelistedUrl(url, project, teamConfig)) {
                        val lineNumber = document.getLineNumber(element.textOffset) + 1
                        violations.add(
                            SecurityViolation(
                                file = psiFile.virtualFile,
                                line = lineNumber,
                                content = text,
                                message = "Non-whitelisted URL in string literal: $url. Verify this domain is intentional.",
                                riskLevel = RiskLevel.MEDIUM
                            )
                        )
                    }
                }
            }
        })
        return violations
    }

    /**
     * Extracts string literal content using platform-generic APIs only.
     * Works in both K1 and K2 Kotlin mode — no compiler-internal classes used.
     */
    private fun extractStringLiteral(element: PsiElement): String? {
        // 1. Platform-generic interface — covers Java, Groovy, and some Kotlin literals
        if (element is PsiLiteralValue) {
            val value = element.value
            if (value is String) return value
        }

        // 2. Text-based fallback for Kotlin string templates and Groovy GStrings
        //    We only match leaf-level elements whose class name indicates a string literal
        val className = element.javaClass.simpleName
        if (className.contains("StringTemplate") || className.contains("Literal") || className.contains("GString")) {
            val raw = element.text ?: return null
            // Strip surrounding quotes
            return raw
                .removeSurrounding("\"\"\"")
                .removeSurrounding("\"")
                .removeSurrounding("'")
                .ifBlank { null }
        }

        return null
    }

    companion object {
        private val urlPattern = Pattern.compile("(http|https)://(?!localhost|127\\.0\\.0\\.1)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", Pattern.CASE_INSENSITIVE)
    }
}
