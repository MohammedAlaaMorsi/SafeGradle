package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project

object WhitelistConfig {
    // Built-in safe domains (never flagged)
    private val builtInWhitelist = setOf(
        // Gradle official
        "gradle.org",
        "plugins.gradle.org",
        "services.gradle.org",
        "downloads.gradle.org",
        "downloads.gradle-dn.com",
        "artifacts.gradle.org",
        // Maven Central / Sonatype
        "repo.maven.apache.org",
        "repo1.maven.org",
        "central.sonatype.com",
        "oss.sonatype.org",
        "s01.oss.sonatype.org",
        "repository.sonatype.org",
        // Google / Android
        "dl.google.com",
        "maven.google.com",
        "storage.googleapis.com",
        // JetBrains / Kotlin
        "plugins.jetbrains.com",
        "packages.jetbrains.team",
        "cache-redirector.jetbrains.com",
        // GitHub
        "maven.pkg.github.com",
        "raw.githubusercontent.com",
        "github.com",
        // Apache
        "repository.apache.org",
        "repo.maven.apache.org",
        // Spring
        "repo.spring.io",
        // Community / misc registries
        "jitpack.io",
        "clojars.org",
        "packages.microsoft.com",
        "nuget.pkg.github.com",
        // Common CDNs used by build tools
        "cloudfront.net",
        "azureedge.net",
        // Firebase / Fabric
        "maven.fabric.io",
        "dl.firebase.io",
        // Atlassian
        "maven.atlassian.com",
        "packages.atlassian.com",
        // npm (sometimes referenced in multi-platform builds)
        "registry.npmjs.org"
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
