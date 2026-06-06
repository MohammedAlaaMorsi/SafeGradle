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
}
