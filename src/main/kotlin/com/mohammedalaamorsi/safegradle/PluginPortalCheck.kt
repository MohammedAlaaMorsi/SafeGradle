package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

class PluginPortalCheck : SecurityCheck {
    override val id = "gradle_plugin"
    override val name = "Gradle Plugin Supply Chain"
    override val description = "Flags plugin IDs that impersonate popular Gradle plugins, abandoned plugin IDs, and unpinned plugin versions."

    // Plugins that run with full build privileges on every developer machine — prime typosquatting targets
    private val popularPlugins = setOf(
        "com.android.application", "com.android.library", "com.android.test",
        "org.jetbrains.kotlin.jvm", "org.jetbrains.kotlin.android", "org.jetbrains.kotlin.multiplatform",
        "org.jetbrains.kotlin.js", "org.jetbrains.kotlin.plugin.serialization", "org.jetbrains.kotlin.plugin.compose",
        "org.jetbrains.kotlin.kapt", "org.jetbrains.kotlin.plugin.parcelize", "org.jetbrains.kotlin.plugin.spring",
        "org.jetbrains.compose", "org.jetbrains.dokka", "org.jetbrains.intellij.platform", "org.jetbrains.kotlinx.kover",
        "com.google.devtools.ksp", "com.google.gms.google-services", "com.google.firebase.crashlytics",
        "com.google.dagger.hilt.android", "com.google.protobuf", "androidx.navigation.safeargs.kotlin", "androidx.room",
        "org.springframework.boot", "io.spring.dependency-management", "io.micronaut.application", "io.quarkus",
        "com.gradleup.shadow", "com.diffplug.spotless", "io.gitlab.arturbosch.detekt", "org.jlleitschuh.gradle.ktlint",
        "com.github.ben-manes.versions", "com.vanniktech.maven.publish", "io.github.gradle-nexus.publish-plugin",
        "com.gradle.plugin-publish", "com.gradle.develocity", "org.sonarqube", "io.freefair.lombok", "org.openapi.generator"
    )

    // Plugin IDs whose maintainers moved on — the old ID gets no security fixes
    private val relocatedPlugins = mapOf(
        "com.github.johnrengelman.shadow" to "com.gradleup.shadow",
        "com.gradle.enterprise" to "com.gradle.develocity",
        "io.codearte.nexus-staging" to "io.github.gradle-nexus.publish-plugin",
        "org.jetbrains.intellij" to "org.jetbrains.intellij.platform"
    )

    // id("x") version "y"  |  id 'x' version 'y'  |  TOML: { id = "x", version = "y" }
    private val scriptPlugin = Regex("""\bid\s*\(?\s*["']([A-Za-z0-9._-]+)["']\s*\)?(?:\s*version\s*\(?\s*["']([^"']+)["'])?""")
    private val tomlPlugin = Regex("""\bid\s*=\s*"([A-Za-z0-9._-]+)"(?:.*?\bversion\s*=\s*"([^"]+)")?""")

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val isToml = file.name.endsWith(".toml")
        if (!isToml && !file.name.startsWith("build.gradle") && !file.name.startsWith("settings.gradle")) return emptyList()
        val violations = mutableListOf<SecurityViolation>()
        var inTomlPlugins = false

        content.lines().forEachIndexed { index, rawLine ->
            val line = if (isToml) rawLine.substringBefore('#') else SecurityUtils.stripComments(rawLine)
            if (isToml && line.trim().startsWith("[")) inTomlPlugins = line.trim() == "[plugins]"
            if (isToml && !inTomlPlugins) return@forEachIndexed

            val m = (if (isToml) tomlPlugin else scriptPlugin).find(line) ?: return@forEachIndexed
            val pluginId = m.groupValues[1]
            val version = m.groupValues[2]
            fun add(level: RiskLevel, msg: String) {
                violations += SecurityViolation(file = file, line = index + 1, content = rawLine.trim(), message = msg, riskLevel = level, checkId = id)
            }

            val lookalike = if (pluginId in popularPlugins) null
                else popularPlugins.firstOrNull { isLookalike(pluginId, it) }
            if (lookalike != null) {
                add(RiskLevel.HIGH, "Plugin '$pluginId' is suspiciously similar to the popular plugin '$lookalike'. " +
                    "Plugins run with full access to your machine during the build — verify the ID on plugins.gradle.org.")
            }
            relocatedPlugins[pluginId]?.let { replacement ->
                add(RiskLevel.LOW, "Plugin ID '$pluginId' is no longer maintained under this ID — migrate to '$replacement' to keep receiving security fixes.")
            }
            if (version.endsWith("+") || version.startsWith("latest.") || version.contains("[") || version.contains("(")) {
                add(RiskLevel.MEDIUM, "Plugin '$pluginId' uses a dynamic version '$version' — a newly published (possibly compromised) release " +
                    "would run on the next build without review. Pin an exact version.")
            } else if (version.endsWith("-SNAPSHOT")) {
                add(RiskLevel.LOW, "Plugin '$pluginId' uses a SNAPSHOT version — its contents can change at any time. Pin a release version.")
            }
        }
        return violations
    }

    private fun isLookalike(candidate: String, popular: String): Boolean {
        // Lengthy legit extensions like "com.android.application.foo" aren't typos
        if (candidate.startsWith("$popular.")) return false
        // Same rule as DependencyConfusionCheck: one edit, or two edits at equal length (swapped letters)
        val distance = SecurityUtils.levenshtein(candidate, popular)
        return distance == 1 || (distance == 2 && candidate.length == popular.length)
    }
}
