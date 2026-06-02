package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.VirtualFile
import java.io.InputStream

data class YamlConfig(
    val whitelistDomains: List<String> = emptyList(),
    val suppressions: List<Suppression> = emptyList(),
    val severityOverrides: Map<String, RiskLevel?> = emptyMap(),
    // URL prefixes allowed in `apply from:` — everything else is flagged
    val allowedScriptSources: List<String> = emptyList()
)

data class Suppression(
    val checkId: String,
    val file: String,
    val line: Int? = null,
    val reason: String? = null
)

object YamlConfigParser {
    fun parse(inputStream: InputStream): YamlConfig {
        val lines = inputStream.bufferedReader().readLines()
        val whitelist = mutableListOf<String>()
        val suppressions = mutableListOf<Suppression>()
        val severityOverrides = mutableMapOf<String, RiskLevel?>()

        var currentSection = ""
        var currentSuppression: MutableMap<String, String>? = null
        val allowedScriptSources = mutableListOf<String>()

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue

            when {
                line.startsWith("whitelist_domains:") -> { currentSection = "whitelist"; continue }
                line.startsWith("suppressions:") -> { currentSection = "suppressions"; continue }
                line.startsWith("severity_overrides:") -> { currentSection = "severity_overrides"; continue }
                line.startsWith("allowed_script_sources:") -> { currentSection = "allowed_script_sources"; continue }
            }

            when (currentSection) {
                "whitelist" -> if (trimmed.startsWith("-")) whitelist.add(trimmed.removePrefix("-").trim())
                "suppressions" -> {
                    if (trimmed.startsWith("-")) {
                        currentSuppression?.let { suppressions.add(mapToSuppression(it)) }
                        currentSuppression = mutableMapOf()
                        val firstKeyVal = trimmed.removePrefix("-").trim().split(":", limit = 2)
                        if (firstKeyVal.size == 2) currentSuppression[firstKeyVal[0].trim()] = firstKeyVal[1].trim()
                    } else if (currentSuppression != null && trimmed.contains(":")) {
                        val keyVal = trimmed.split(":", limit = 2)
                        currentSuppression[keyVal[0].trim()] = keyVal[1].trim()
                    }
                }
                "severity_overrides" -> {
                    if (trimmed.contains(":")) {
                        val keyVal = trimmed.split(":", limit = 2)
                        val checkId = keyVal[0].trim()
                        val level = keyVal[1].trim().uppercase()
                        severityOverrides[checkId] = when (level) {
                            "HIGH" -> RiskLevel.HIGH
                            "MEDIUM" -> RiskLevel.MEDIUM
                            "LOW" -> RiskLevel.LOW
                            "NONE", "MUTE", "OFF", "DISABLED" -> null
                            else -> null
                        }
                    }
                }
                "allowed_script_sources" -> {
                    if (trimmed.startsWith("-")) allowedScriptSources.add(trimmed.removePrefix("-").trim())
                }
            }
        }
        currentSuppression?.let { suppressions.add(mapToSuppression(it)) }

        return YamlConfig(whitelist, suppressions, severityOverrides, allowedScriptSources)
    }

    private fun mapToSuppression(map: Map<String, String>): Suppression {
        return Suppression(
            checkId = map["check"] ?: "",
            file = map["file"] ?: "",
            line = map["line"]?.toIntOrNull(),
            reason = map["reason"]
        )
    }
}
