package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class PluginInjectionCheck : SecurityCheck {
    override val id = "plugin_injection"
    override val name = "Suspicious Plugin Injection"
    override val description = "Detects application of unknown or suspicious Gradle plugins that could execute malicious code during the build."

    private val knownSafePlugins = setOf(
        "java", "kotlin", "application", "com.android.application",
        "com.android.library", "org.jetbrains.kotlin.jvm",
        "org.springframework.boot", "io.spring.dependency-management",
        "maven-publish", "signing", "checkstyle", "pmd", "jacoco",
        "com.google.gms.google-services", "com.google.firebase.crashlytics",
        "org.jetbrains.intellij", "org.jetbrains.changelog", "org.jetbrains.qodana"
    )

    private val pluginPattern = Pattern.compile("(id|plugin)\\s*[\\(\"']\\s*([^\"'\\)]+)\\s*[\\)\"']", Pattern.CASE_INSENSITIVE)
    private val applyPattern = Pattern.compile("apply\\s+plugin:\\s*['\"]([^'\"]+)['\"]", Pattern.CASE_INSENSITIVE)

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("//")) return@forEachIndexed

            val m1 = pluginPattern.matcher(line)
            while (m1.find()) {
                val pluginId = m1.group(2).trim()
                if (!isKnownSafe(pluginId)) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Suspicious plugin detected: '$pluginId'. Verify this plugin is from a trusted source.",
                            riskLevel = RiskLevel.MEDIUM
                        )
                    )
                }
            }

            val m2 = applyPattern.matcher(line)
            while (m2.find()) {
                val pluginId = m2.group(1).trim()
                if (!isKnownSafe(pluginId)) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Suspicious legacy plugin application: '$pluginId'.",
                            riskLevel = RiskLevel.MEDIUM
                        )
                    )
                }
            }
        }
        return violations
    }

    private fun isKnownSafe(id: String): Boolean {
        if (knownSafePlugins.contains(id)) return true
        // Allow common prefixes
        if (id.startsWith("com.android.") || id.startsWith("org.jetbrains.") || id.startsWith("com.google.")) return true
        return false
    }
}
