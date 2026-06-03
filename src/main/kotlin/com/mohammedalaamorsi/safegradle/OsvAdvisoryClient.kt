package com.mohammedalaamorsi.safegradle

import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

data class OsvVulnerability(val id: String, val summary: String)

object OsvAdvisoryClient {

    private const val OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
    private const val TIMEOUT_MS = 8_000

    // Returns a map of "group:artifact:version" → list of vulnerabilities found for it.
    // Only packages that have findings appear in the result.
    fun queryBatch(packages: List<Triple<String, String, String>>): Map<String, List<OsvVulnerability>> {
        if (packages.isEmpty()) return emptyMap()

        val body = buildRequestBody(packages)
        val responseText = try {
            post(body)
        } catch (e: Exception) {
            return emptyMap()
        }

        return parseResponse(packages, responseText)
    }

    private fun buildRequestBody(packages: List<Triple<String, String, String>>): String {
        val queries = packages.joinToString(",\n") { (group, artifact, version) ->
            """{"package":{"name":"$group:$artifact","ecosystem":"Maven"},"version":"$version"}"""
        }
        return """{"queries":[$queries]}"""
    }

    private fun post(body: String): String {
        val conn = java.net.URI(OSV_BATCH_URL).toURL().openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.doOutput = true
        OutputStreamWriter(conn.outputStream).use { it.write(body) }
        return conn.inputStream.bufferedReader().readText()
    }

    // Minimal JSON parsing without external libs — extracts id and summary from each result block
    private fun parseResponse(
        packages: List<Triple<String, String, String>>,
        json: String
    ): Map<String, List<OsvVulnerability>> {
        val result = mutableMapOf<String, List<OsvVulnerability>>()

        // Split on "results":[...] — each element corresponds to the same index in packages
        val resultsBlock = json.substringAfter("\"results\":[", "").trimEnd('}', ']')
        if (resultsBlock.isBlank()) return result

        // Each item is either {} (no vulns) or {"vulns":[...]}
        val items = splitTopLevelObjects(resultsBlock)
        items.forEachIndexed { idx, item ->
            val pkg = packages.getOrNull(idx) ?: return@forEachIndexed
            val key = "${pkg.first}:${pkg.second}:${pkg.third}"
            if (!item.contains("\"vulns\"")) return@forEachIndexed

            val vulns = extractVulns(item)
            if (vulns.isNotEmpty()) result[key] = vulns
        }
        return result
    }

    private fun extractVulns(item: String): List<OsvVulnerability> {
        val list = mutableListOf<OsvVulnerability>()
        val idRegex = Regex(""""id"\s*:\s*"([^"]+)"""")
        val summaryRegex = Regex(""""summary"\s*:\s*"([^"]+)"""")
        val ids = idRegex.findAll(item).map { it.groupValues[1] }.toList()
        val summaries = summaryRegex.findAll(item).map { it.groupValues[1] }.toList()
        ids.forEachIndexed { i, id -> list.add(OsvVulnerability(id, summaries.getOrElse(i) { "" })) }
        return list
    }

    // Splits a JSON array body (without outer [ ]) into top-level object strings
    private fun splitTopLevelObjects(s: String): List<String> {
        val items = mutableListOf<String>()
        var depth = 0
        var start = -1
        for (i in s.indices) {
            when (s[i]) {
                '{' -> { if (depth == 0) start = i; depth++ }
                '}' -> {
                    depth--
                    if (depth == 0 && start >= 0) {
                        items.add(s.substring(start, i + 1))
                        start = -1
                    }
                }
            }
        }
        return items
    }
}
