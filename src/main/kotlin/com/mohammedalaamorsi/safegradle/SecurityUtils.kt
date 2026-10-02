package com.mohammedalaamorsi.safegradle

object SecurityUtils {
    fun stripComments(line: String): String {
        var inString = false
        var stringChar = ' '
        var i = 0
        while (i < line.length) {
            val c = line[i]
            if (inString) {
                if (c == '\\') { i += 2; continue }
                if (c == stringChar) inString = false
            } else {
                if (c == '"' || c == '\'') { inString = true; stringChar = c }
                else if (c == '/' && i + 1 < line.length && line[i + 1] == '/') {
                    return line.substring(0, i)
                }
            }
            i++
        }
        return line
    }

    /**
     * Checks if a line is likely part of a safe Gradle block.
     */
    fun isLikelySafeBlock(line: String): Boolean {
        val trimmed = line.trim()
        return trimmed.startsWith("repositories") ||
                trimmed.startsWith("pluginManagement") ||
                trimmed.startsWith("dependencyResolutionManagement") ||
                trimmed.startsWith("buildscript") ||
                trimmed.startsWith("allprojects") ||
                trimmed.startsWith("subprojects")
    }

    fun levenshtein(s1: String, s2: String): Int {
        val dp = Array(s1.length + 1) { IntArray(s2.length + 1) }
        for (i in 0..s1.length) dp[i][0] = i
        for (j in 0..s2.length) dp[0][j] = j
        for (i in 1..s1.length) {
            for (j in 1..s2.length) {
                val cost = if (s1[i - 1] == s2[j - 1]) 0 else 1
                dp[i][j] = minOf(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
            }
        }
        return dp[s1.length][s2.length]
    }
}
