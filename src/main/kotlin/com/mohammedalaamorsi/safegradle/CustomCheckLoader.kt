package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

// User-defined checks: place .kts scripts in .safegradle/checks/.
// Each script uses comment directives:
//   # PATTERN: <regex>  RISK: HIGH|MEDIUM|LOW  MSG: <message>
// Lines matching the regex are flagged at the given risk level.
object CustomCheckLoader {

    fun loadChecks(project: Project): List<SecurityCheck> {
        val baseDir = project.basePath ?: return emptyList()
        val checksDir = java.io.File(baseDir, ".safegradle/checks")
        if (!checksDir.exists() || !checksDir.isDirectory) return emptyList()

        return checksDir.listFiles { f -> f.extension == "kts" }
            ?.mapNotNull { scriptFile ->
                try {
                    ScriptBasedCheck(scriptFile)
                } catch (e: Exception) {
                    null // skip malformed scripts silently
                }
            } ?: emptyList()
    }
}

class ScriptBasedCheck(private val scriptFile: java.io.File) : SecurityCheck {
    override val id = "custom_${scriptFile.nameWithoutExtension}"
    override val name = "Custom: ${scriptFile.nameWithoutExtension}"
    override val description = "User-defined check loaded from .safegradle/checks/${scriptFile.name}"

    // Parse the script once: extract inline patterns from comment directives.
    // Supported directive: # PATTERN: <regex> [RISK: HIGH|MEDIUM|LOW] [MSG: <message>]
    private data class CustomRule(val pattern: java.util.regex.Pattern, val message: String, val risk: RiskLevel)

    private val rules: List<CustomRule> = parseRules()

    private fun parseRules(): List<CustomRule> {
        val result = mutableListOf<CustomRule>()
        scriptFile.readLines().forEach { line ->
            val trimmed = line.trim()
            if (!trimmed.startsWith("# PATTERN:") && !trimmed.startsWith("// PATTERN:")) return@forEach
            try {
                val withoutPrefix = trimmed.removePrefix("# PATTERN:").removePrefix("// PATTERN:").trim()
                val riskMatch = Regex("""\bRISK:\s*(HIGH|MEDIUM|LOW)\b""", RegexOption.IGNORE_CASE).find(withoutPrefix)
                val msgMatch = Regex("""\bMSG:\s*(.+)$""").find(withoutPrefix)
                val risk = when (riskMatch?.groupValues?.get(1)?.uppercase()) {
                    "HIGH" -> RiskLevel.HIGH
                    "LOW" -> RiskLevel.LOW
                    else -> RiskLevel.MEDIUM
                }
                val message = msgMatch?.groupValues?.get(1)?.trim() ?: "Custom rule matched: ${scriptFile.nameWithoutExtension}"
                val patternEnd = riskMatch?.range?.first?.minus(1) ?: msgMatch?.range?.first?.minus(1) ?: withoutPrefix.length
                val patternStr = withoutPrefix.substring(0, patternEnd).trim()
                result.add(CustomRule(java.util.regex.Pattern.compile(patternStr, java.util.regex.Pattern.CASE_INSENSITIVE), message, risk))
            } catch (_: Exception) { } // skip malformed directive lines
        }
        return result
    }

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (rules.isEmpty()) return emptyList()
        val violations = mutableListOf<SecurityViolation>()
        content.lines().forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("//") || stripped.startsWith("#")) return@forEachIndexed
            for (rule in rules) {
                if (rule.pattern.matcher(line).find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = stripped,
                            message = rule.message,
                            riskLevel = rule.risk,
                            checkId = id
                        )
                    )
                }
            }
        }
        return violations
    }
}
