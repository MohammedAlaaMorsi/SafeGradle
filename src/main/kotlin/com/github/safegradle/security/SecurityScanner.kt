package com.github.safegradle.security

import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.search.FilenameIndex
import com.intellij.psi.search.GlobalSearchScope

class SecurityScanner() {
    private val checks = listOf(
        ShellExecutionCheck(),
        NetworkActivityCheck(),
        SensitiveFileCheck(),
        ObfuscationCheck(),
        SystemTamperingCheck()
    )

    fun scanProject(project: Project): Map<VirtualFile, List<SecurityViolation>> {
        val baseDir = project.guessProjectDir() ?: return emptyMap()
        return scanDirectory(baseDir)
    }

    fun scanDirectory(dir: VirtualFile): Map<VirtualFile, List<SecurityViolation>> {
        val results = mutableMapOf<VirtualFile, List<SecurityViolation>>()
        
        // Find all Gradle-related files via manual recursion since we might not have a Project index yet
        val fileNames = listOf(
            "build.gradle", "build.gradle.kts",
            "settings.gradle", "settings.gradle.kts",
            "gradle.properties"
        )
        
        val filesToScan = mutableListOf<VirtualFile>()
        collectFiles(dir, fileNames, filesToScan)

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

    private fun collectFiles(dir: VirtualFile, fileNames: List<String>, result: MutableList<VirtualFile>) {
        if (!dir.isDirectory) return
        
        // Skip common large directories to speed up scanning
        if (dir.name == ".git" || dir.name == ".gradle" || dir.name == ".idea" || dir.name == "build") {
            return
        }

        for (child in dir.children) {
            if (child.isDirectory) {
                collectFiles(child, fileNames, result)
            } else if (fileNames.contains(child.name)) {
                result.add(child)
            }
        }
    }
}
