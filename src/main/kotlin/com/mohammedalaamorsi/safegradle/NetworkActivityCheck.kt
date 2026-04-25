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
        // Simple regex for IP addresses (excluding localhost 127.0.0.1)
        Pattern.compile("(http|https)://(?!localhost|127\\.0\\.0\\.1)[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", Pattern.CASE_INSENSITIVE)
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

            // Skip legitimate dependency declarations and plugin repositories or safe blocks
            if (currentInsideSafeBlock ||
                strippedLine.startsWith("maven") || 
                strippedLine.startsWith("google()") || 
                strippedLine.startsWith("jcenter()") ||
                strippedLine.startsWith("classpath") ||
                strippedLine.startsWith("implementation") ||
                strippedLine.startsWith("api")) {
                return@forEachIndexed
            }

            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
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
                                message = "Semantic detection: Suspicious URL in string literal: $url",
                                riskLevel = RiskLevel.HIGH
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
