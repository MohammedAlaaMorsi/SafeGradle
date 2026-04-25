package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class DependencyConfusionCheck : SecurityCheck {
    override val id = "dependency_confusion"
    override val name = "Dependency Confusion / Typosquatting"
    override val description = "Detects dependencies that may be impersonating popular libraries (e.g., 'gooogle' vs 'google')."

    // Simple list of popular group IDs to check against
    private val popularGroups = setOf(
        "com.google", "org.jetbrains", "androidx", "com.android",
        "org.springframework", "com.square", "com.jakewharton", "org.apache"
    )

    private val dependencyPattern = Pattern.compile("['\"]([^'\"]+):([^'\"]+):([^'\"]+)['\"]")

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            val matcher = dependencyPattern.matcher(line)
            if (matcher.find()) {
                val group = matcher.group(1)
                
                // Check for common typos or suspicious patterns in popular groups
                for (popular in popularGroups) {
                    if (group != popular && isSuspiciouslySimilar(group, popular)) {
                        violations.add(
                            SecurityViolation(
                                file = file,
                                line = index + 1,
                                content = line.trim(),
                                message = "Potential typosquatting detected! '$group' is suspiciously similar to popular group '$popular'.",
                                riskLevel = RiskLevel.HIGH
                            )
                        )
                    }
                }
            }
        }
        return violations
    }

    private fun isSuspiciouslySimilar(s1: String, s2: String): Boolean {
        // Levenshtein distance or simple substring check
        if (s1.contains(s2) && s1.length > s2.length + 3) return false // legitimate sub-package
        
        // Check for common typos like double letters or swapped letters
        val distance = levenshteinDistance(s1, s2)
        return distance == 1 || (distance == 2 && s1.length == s2.length)
    }

    private fun levenshteinDistance(s1: String, s2: String): Int {
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
