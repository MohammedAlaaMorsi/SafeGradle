package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project

object WhitelistConfig {
    // Built-in safe domains (never flagged)
    private val builtInWhitelist = setOf(
        "gradle.org",
        "plugins.gradle.org",
        "services.gradle.org",
        "repo.maven.apache.org",
        "repo1.maven.org",
        "central.sonatype.com",
        "jcenter.bintray.com",
        "dl.google.com",
        "maven.google.com",
        "kotlin.bintray.com",
        "plugins.jetbrains.com",
        "packages.jetbrains.team",
        "maven.pkg.github.com",
        "registry.npmjs.org",
        "jitpack.io",
        "oss.sonatype.org",
        "s01.oss.sonatype.org",
        "repository.apache.org",
        "clojars.org",
        "repo.spring.io",
        "maven.fabric.io",
        "maven.atlassian.com",
        "raw.githubusercontent.com",
        "github.com"
    )

    fun isWhitelistedUrl(url: String, project: Project? = null, teamConfig: YamlConfig? = null): Boolean {
        val domain = try {
            url.removePrefix("https://").removePrefix("http://")
                .substringBefore("/").substringBefore(":")
        } catch (e: Exception) {
            return false
        }
        
        // 1. Check built-in whitelist
        if (builtInWhitelist.any { domain == it || domain.endsWith(".$it") }) return true
        
        // 2. Check team-wide whitelist (.safegradle.yml)
        if (teamConfig != null && teamConfig.whitelistDomains.any { domain == it || domain.endsWith(".$it") }) return true

        // 3. Check user-defined whitelist in settings
        if (project != null) {
            val settings = SafeGradleSettings.getInstance(project).state
            if (settings.whitelistedDomains.any { domain == it || domain.endsWith(".$it") }) return true
        }
        
        return false
    }
}
