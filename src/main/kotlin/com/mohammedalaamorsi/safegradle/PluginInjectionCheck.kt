package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class PluginInjectionCheck : SecurityCheck {
    override val id = "plugin_injection"
    override val name = "Suspicious Plugin Injection"
    override val description = "Detects application of unknown or suspicious Gradle plugins that could execute malicious code during the build."

    private val knownSafePlugins = setOf(
        // Core Gradle / Java
        "java", "java-library", "java-platform", "java-gradle-plugin",
        "application", "distribution", "war", "ear",
        "groovy", "scala", "antlr", "cpp", "c", "assembler",
        // Kotlin
        "kotlin", "kotlin-android", "kotlin-kapt", "kotlin-parcelize", "kotlin-android-extensions",
        "org.jetbrains.kotlin.jvm", "org.jetbrains.kotlin.android",
        "org.jetbrains.kotlin.multiplatform", "org.jetbrains.kotlin.native.cocoapods",
        "org.jetbrains.kotlin.plugin.serialization", "org.jetbrains.kotlin.plugin.compose",
        // Android
        "com.android.application", "com.android.library", "com.android.test",
        "com.android.dynamic-feature", "com.android.asset-pack",
        // Spring
        "org.springframework.boot", "io.spring.dependency-management",
        // Publishing / signing
        "maven-publish", "ivy-publish", "signing", "com.gradle.plugin-publish",
        // Quality / linting
        "checkstyle", "pmd", "findbugs", "spotbugs", "jacoco",
        "io.gitlab.arturbosch.detekt",
        "org.jlleitschuh.gradle.ktlint",
        "com.diffplug.spotless",
        "org.sonarqube",
        // Testing
        "org.gradle.test-retry",
        // IntelliJ Platform
        "org.jetbrains.intellij", "org.jetbrains.intellij.platform",
        "org.jetbrains.changelog", "org.jetbrains.qodana",
        // Firebase / Google
        "com.google.gms.google-services",
        "com.google.firebase.crashlytics",
        "com.google.firebase.firebase-perf",
        // Dependency management
        "com.github.ben-manes.versions",
        "nl.littlerobots.version-catalog-update",
        "com.autonomousapps.dependency-analysis",
        // Build / release
        "net.researchgate.release",
        "com.github.triplet.play",
        "io.github.gradle-nexus.publish-plugin",
        "de.undercouch.download",
        // Misc common plugins
        "com.gorylenko.gradle-git-properties",
        "com.github.johnrengelman.shadow",
        "com.palantir.git-version",
        "com.osacky.doctor",
        "org.gradle.wrapper",
        "base", "build-dashboard", "help-tasks", "project-report",
        "lifecycle-base", "reporting-base"
    )

    // Trusted vendor prefixes — any plugin under these namespaces is allowed
    private val trustedPrefixes = listOf(
        "com.android.",
        "org.jetbrains.",
        "com.google.",
        "io.ktor.",
        "com.squareup.",
        "io.spring.",
        "org.springframework.",
        "io.github.gradle-nexus.",
        "io.github.",
        "com.diffplug.",
        "org.jlleitschuh.",
        "io.gitlab.arturbosch.",
        "net.researchgate.",
        "nu.studer.",
        "com.github.ben-manes.",
        "com.github.johnrengelman.",
        "com.palantir.",
        "de.undercouch.",
        "com.gorylenko.",
        "com.github.triplet.",
        "io.sentry.",
        "org.sonarqube",
        "gradle.plugin."
    )

    private val pluginPattern = Pattern.compile(
        "(id|plugin)\\s*[\\(\"']\\s*([^\"'\\)]+)\\s*[\\)\"']",
        Pattern.CASE_INSENSITIVE
    )
    private val applyPattern = Pattern.compile(
        "apply\\s+plugin:\\s*['\"]([^'\"]+)['\"]",
        Pattern.CASE_INSENSITIVE
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("//") || stripped.startsWith("#")) return@forEachIndexed

            val m1 = pluginPattern.matcher(line)
            while (m1.find()) {
                val pluginId = m1.group(2).trim()
                if (!isKnownSafe(pluginId)) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = stripped,
                            message = "Unknown plugin '$pluginId'. Verify it comes from a trusted source before enabling it.",
                            riskLevel = RiskLevel.LOW
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
                            content = stripped,
                            message = "Unknown plugin applied via legacy syntax: '$pluginId'. Verify it comes from a trusted source.",
                            riskLevel = RiskLevel.LOW
                        )
                    )
                }
            }
        }
        return violations
    }

    private fun isKnownSafe(id: String): Boolean {
        if (knownSafePlugins.contains(id)) return true
        return trustedPrefixes.any { id.startsWith(it) }
    }
}
