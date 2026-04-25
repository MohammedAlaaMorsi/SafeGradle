package com.mohammedalaamorsi.safegradle

object SecurityUtils {
    /**
     * Strips single-line comments from a line.
     * Note: This is a simple implementation and doesn't handle strings containing // correctly.
     * In a full implementation, we'd use a lexer or more complex regex.
     */
    fun stripComments(line: String): String {
        val commentIndex = line.indexOf("//")
        return if (commentIndex >= 0) {
            line.substring(0, commentIndex)
        } else {
            line
        }
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
