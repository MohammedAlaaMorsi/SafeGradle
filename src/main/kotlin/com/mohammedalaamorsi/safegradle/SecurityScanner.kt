package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.LocalFileSystem

import com.intellij.openapi.application.runReadAction
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.PsiManager

class SecurityScanner() {
    private val checks = listOf(
        ShellExecutionCheck(),
        NetworkActivityCheck(),
        SensitiveFileCheck(),
        ObfuscationCheck(),
        SystemTamperingCheck(),
        CredentialLeakCheck(),
        FileExfiltrationCheck(),
        GradleWrapperIntegrityCheck(),
        DependencyConfusionCheck(),
        PluginInjectionCheck(),
        VulnerabilityCheck()
    )

    fun scanProject(project: Project): Map<VirtualFile, List<SecurityViolation>> {
        val baseDir = project.guessProjectDir() ?: return emptyMap()
        
        // Load team-wide config if exists
        val configFile = baseDir.findChild(".safegradle.yml")
        val teamConfig = configFile?.let { 
            try {
                YamlConfigParser.parse(it.inputStream)
            } catch (e: Exception) {
                null
            }
        }

        val results = scanDirectory(baseDir, project, teamConfig).toMutableMap()
        
        // Scan global init scripts as well (Production Hardening)
        val userHome = System.getProperty("user.home")
        val globalInitDir = LocalFileSystem.getInstance().findFileByPath("$userHome/.gradle/init.d")
        if (globalInitDir != null && globalInitDir.isDirectory) {
            val globalResults = scanDirectory(globalInitDir, project, teamConfig)
            results.putAll(globalResults)
        }

        return results
    }

    fun scanDirectory(dir: VirtualFile, project: Project? = null, teamConfig: YamlConfig? = null): Map<VirtualFile, List<SecurityViolation>> {
        val results = mutableMapOf<VirtualFile, List<SecurityViolation>>()
        
        // Find all Gradle-related files via manual recursion since we might not have a Project index yet
        val fileNames = listOf(
            "build.gradle", "build.gradle.kts",
            "settings.gradle", "settings.gradle.kts",
            "gradle.properties", "gradle-wrapper.jar"
        )
        
        val filesToScan = mutableListOf<VirtualFile>()
        collectFiles(dir, fileNames, filesToScan)

        for (file in filesToScan) {
            if (!file.isValid || file.isDirectory) continue

            // 1. Check cache first (Performance Enhancement)
            if (project != null) {
                val cached = SafeGradleScanCache.getInstance(project).getCachedViolations(file)
                if (cached != null) {
                    if (cached.isNotEmpty()) {
                        results[file] = cached
                    }
                    continue
                }
            }

            try {
                // Read file content
                val content = String(file.contentsToByteArray())
                val fileViolations = mutableListOf<SecurityViolation>()
                val settings = project?.let { SafeGradleSettings.getInstance(it).state }
                
                // Load PSI file for semantic analysis if needed
                val psiFile = project?.let { proj ->
                    runReadAction { PsiManager.getInstance(proj).findFile(file) }
                }

                for (check in checks) {
                    // Combine Regex and PSI violations
                    val rawViolations = mutableListOf<SecurityViolation>()
                    rawViolations.addAll(check.check(file, content, project, teamConfig))
                    
                    if (psiFile != null) {
                        runReadAction {
                            rawViolations.addAll(check.checkPsi(psiFile, project, teamConfig))
                        }
                    }
                    
                    // Filter violations
                    val filtered = rawViolations.filter { violation ->
                        // 1. Check for inline ignore comment
                        val lineContent = content.lines().getOrNull(violation.line - 1) ?: ""
                        if (lineContent.contains("safegradle:ignore")) {
                            return@filter false
                        }

                        // 2. Check for team-wide suppression (.safegradle.yml)
                        if (teamConfig != null) {
                            val isSuppressedInYaml = teamConfig.suppressions.any { s ->
                                (s.checkId == check.id || s.checkId == "all") &&
                                (file.path.endsWith(s.file)) &&
                                (s.line == null || s.line == violation.line)
                            }
                            if (isSuppressedInYaml) return@filter false
                        }

                        // 3. Check for persisted ignore in settings
                        if (settings != null) {
                            val isIgnoredInSettings = settings.ignoredViolations.any {
                                it.filePath == file.path && it.line == violation.line && it.checkId == check.id
                            }
                            if (isIgnoredInSettings) {
                                return@filter false
                            }
                        }

                        true
                    }
                    fileViolations.addAll(filtered)
                }

                if (fileViolations.isNotEmpty()) {
                    results[file] = fileViolations
                }
                
                // Update cache
                if (project != null) {
                    SafeGradleScanCache.getInstance(project).updateCache(file, fileViolations)
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
