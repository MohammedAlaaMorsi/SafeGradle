package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.VirtualFile
import java.io.InputStream

data class YamlConfig(
    val whitelistDomains: List<String> = emptyList(),
    val suppressions: List<Suppression> = emptyList()
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
        
        var currentSection = ""
        var currentSuppression: MutableMap<String, String>? = null

        for (line in lines) {
            val trimmed = line.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("#")) continue

            if (line.startsWith("whitelist_domains:")) {
                currentSection = "whitelist"
                continue
            } else if (line.startsWith("suppressions:")) {
                currentSection = "suppressions"
                continue
            }

            if (currentSection == "whitelist" && trimmed.startsWith("-")) {
                whitelist.add(trimmed.removePrefix("-").trim())
            } else if (currentSection == "suppressions") {
                if (trimmed.startsWith("-")) {
                    // New suppression entry
                    currentSuppression?.let { suppressions.add(mapToSuppression(it)) }
                    currentSuppression = mutableMapOf()
                    val firstKeyVal = trimmed.removePrefix("-").trim().split(":", limit = 2)
                    if (firstKeyVal.size == 2) {
                        currentSuppression[firstKeyVal[0].trim()] = firstKeyVal[1].trim()
                    }
                } else if (currentSuppression != null && trimmed.contains(":")) {
                    val keyVal = trimmed.split(":", limit = 2)
                    currentSuppression[keyVal[0].trim()] = keyVal[1].trim()
                }
            }
        }
        currentSuppression?.let { suppressions.add(mapToSuppression(it)) }

        return YamlConfig(whitelist, suppressions)
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
