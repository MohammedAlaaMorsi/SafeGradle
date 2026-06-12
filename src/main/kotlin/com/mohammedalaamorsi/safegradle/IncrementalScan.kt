package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import com.intellij.openapi.vfs.VirtualFile

/**
 * Rescans individual files and merges the outcome into the last published results,
 * so saving one file doesn't trigger a full project tree walk.
 */
object IncrementalScan {

    /** Replaces [rescanned] files' entries in [existing]; files with no violations are dropped. */
    fun merge(
        existing: Map<VirtualFile, List<SecurityViolation>>,
        rescanned: Map<VirtualFile, List<SecurityViolation>>
    ): Map<VirtualFile, List<SecurityViolation>> {
        val merged = existing.toMutableMap()
        for ((file, violations) in rescanned) {
            if (violations.isEmpty()) merged.remove(file) else merged[file] = violations
        }
        return merged
    }

    /**
     * Rescans [files] with full project context (custom checks + team config), updates the
     * cache, and returns the merged result map. Must be called from a background thread.
     */
    fun rescanFiles(project: Project, files: List<VirtualFile>): Map<VirtualFile, List<SecurityViolation>> {
        val scanner = SecurityScanner(CustomCheckLoader.loadChecks(project))
        val teamConfig = loadTeamConfig(project)
        val cache = SafeGradleScanCache.getInstance(project)

        val rescanned = mutableMapOf<VirtualFile, List<SecurityViolation>>()
        for (file in files) {
            cache.invalidate(file)
            val violations = scanner.scanSingleFile(file, project, teamConfig)
            cache.updateCache(file, violations)
            rescanned[file] = violations
        }
        return merge(SafeGradleResultService.getInstance(project).getResults(), rescanned)
    }

    private fun loadTeamConfig(project: Project): YamlConfig? {
        val configFile = project.guessProjectDir()?.findChild(".safegradle.yml") ?: return null
        return try {
            YamlConfigParser.parse(configFile.inputStream)
        } catch (e: Exception) {
            null
        }
    }
}
