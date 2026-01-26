package com.github.safegradle.security

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.search.FilenameIndex
import com.intellij.psi.search.GlobalSearchScope

class SecurityScanner(private val project: Project) {
    private val checks = listOf(
        ShellExecutionCheck(),
        NetworkActivityCheck(),
        SensitiveFileCheck()
    )

    fun scanProject(): Map<VirtualFile, List<SecurityViolation>> {
        val results = mutableMapOf<VirtualFile, List<SecurityViolation>>()
        val scope = GlobalSearchScope.projectScope(project)

        // Find all Gradle-related files
        val fileNames = listOf(
            "build.gradle", "build.gradle.kts",
            "settings.gradle", "settings.gradle.kts",
            "gradle.properties"
        )

        val filesToScan = mutableListOf<VirtualFile>()
        
        fileNames.forEach { name ->
            filesToScan.addAll(FilenameIndex.getVirtualFilesByName(name, scope))
        }

        // Also scan buildSrc if it exists (simplified: just looking for files with these names anywhere)
         // Ideally we'd scan all .gradle/.kts files, but let's stick to name-based for MVP to avoid noise.
         // Let's also add a generic scan for strings "init.gradle" or similar if they show up.

        for (file in filesToScan) {
            if (!file.isValid || file.isDirectory) continue

            try {
                // Read file content
                val content = String(file.contentsToByteArray())
                val fileViolations = mutableListOf<SecurityViolation>()

                for (check in checks) {
                    fileViolations.addAll(check.check(file, content))
                }

                if (fileViolations.isNotEmpty()) {
                    results[file] = fileViolations
                }
            } catch (e: Exception) {
                // Log or ignore read errors
                e.printStackTrace()
            }
        }

        return results
    }
}
