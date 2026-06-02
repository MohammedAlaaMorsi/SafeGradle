package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.application.ReadAction
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.guessProjectDir
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.PsiFile
import com.intellij.psi.PsiManager
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Future

class SecurityScanner(extraChecks: List<SecurityCheck> = emptyList()) {
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
        VulnerabilityCheck(),
        GitignoreExposureCheck(),
        ApplyFromCheck(),
        JvmArgsCheck(),
        WeakCryptoCheck(),
        DependencyLockCheck()
    ) + extraChecks

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

        // Scan buildSrc — full Kotlin/Groovy project that runs before the main build
        val buildSrcDir = baseDir.findChild("buildSrc")
        if (buildSrcDir != null && buildSrcDir.isDirectory) {
            results.putAll(scanBuildSrc(buildSrcDir, project, teamConfig))
        }

        // Scan composite builds declared in settings.gradle(.kts)
        val includedBuilds = resolveIncludedBuilds(baseDir)
        for (includedBuildDir in includedBuilds) {
            results.putAll(scanBuildSrc(includedBuildDir, project, teamConfig))
        }

        // Scan global init scripts as well (Production Hardening)
        val userHome = System.getProperty("user.home")
        val globalInitDir = LocalFileSystem.getInstance().findFileByPath("$userHome/.gradle/init.d")
        if (globalInitDir != null && globalInitDir.isDirectory) {
            results.putAll(scanDirectory(globalInitDir, project, teamConfig))
        }

        return results
    }

    // Scans all source files inside buildSrc or an included build — arbitrary .kt/.groovy/.java
    private fun scanBuildSrc(
        dir: VirtualFile,
        project: Project?,
        teamConfig: YamlConfig?
    ): Map<VirtualFile, List<SecurityViolation>> {
        val results = mutableMapOf<VirtualFile, List<SecurityViolation>>()
        val sourceFiles = mutableListOf<VirtualFile>()
        collectSourceFiles(dir, sourceFiles)

        for (file in sourceFiles) {
            if (!file.isValid || file.isDirectory) continue
            try {
                val content = String(file.contentsToByteArray())
                val fileViolations = mutableListOf<SecurityViolation>()
                for (check in checks) {
                    fileViolations.addAll(check.check(file, content, project, teamConfig))
                }
                if (fileViolations.isNotEmpty()) results[file] = fileViolations
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
        return results
    }

    private fun collectSourceFiles(dir: VirtualFile, result: MutableList<VirtualFile>) {
        if (!dir.isDirectory) return
        if (dir.name == ".git" || dir.name == ".gradle" || dir.name == ".idea" || dir.name == "build") return
        for (child in dir.children) {
            if (child.isDirectory) {
                collectSourceFiles(child, result)
            } else {
                val ext = child.extension?.lowercase()
                if (ext == "kt" || ext == "groovy" || ext == "java" || ext == "kts") {
                    result.add(child)
                }
            }
        }
    }

    // Parses settings.gradle(.kts) to find includeBuild("path") declarations
    private fun resolveIncludedBuilds(baseDir: VirtualFile): List<VirtualFile> {
        val result = mutableListOf<VirtualFile>()
        val settingsFiles = listOf("settings.gradle", "settings.gradle.kts")
        for (name in settingsFiles) {
            val settings = baseDir.findChild(name) ?: continue
            try {
                val content = String(settings.contentsToByteArray())
                val includePattern = java.util.regex.Pattern.compile(
                    """includeBuild\s*[\(\["']\s*([^"'\)\]]+)\s*[\)\]"']""",
                    java.util.regex.Pattern.CASE_INSENSITIVE
                )
                val matcher = includePattern.matcher(content)
                while (matcher.find()) {
                    val path = matcher.group(1).trim()
                    val includedDir = LocalFileSystem.getInstance()
                        .findFileByPath("${baseDir.path}/$path")
                    if (includedDir != null && includedDir.isDirectory) result.add(includedDir)
                }
            } catch (e: Exception) { /* skip */ }
        }
        return result
    }

    fun scanDirectory(dir: VirtualFile, project: Project? = null, teamConfig: YamlConfig? = null): Map<VirtualFile, List<SecurityViolation>> {
        val results = mutableMapOf<VirtualFile, List<SecurityViolation>>()

        val fileNames = listOf(
            "build.gradle", "build.gradle.kts",
            "settings.gradle", "settings.gradle.kts",
            "gradle.properties", "gradle-wrapper.jar",
            "gradle-wrapper.properties",
            "libs.versions.toml",
            ".gitignore"
        )

        val filesToScan = mutableListOf<VirtualFile>()
        collectFiles(dir, fileNames, filesToScan)

        // Serve from cache where possible
        val toScan = mutableListOf<VirtualFile>()
        for (file in filesToScan) {
            if (!file.isValid || file.isDirectory) continue
            if (project != null) {
                val cached = SafeGradleScanCache.getInstance(project).getCachedViolations(file)
                if (cached != null) {
                    if (cached.isNotEmpty()) results[file] = cached
                    continue
                }
            }
            toScan.add(file)
        }

        if (toScan.isEmpty()) return results

        // Scan uncached files in parallel — checks are stateless so this is safe
        val parallelResults = ConcurrentHashMap<VirtualFile, List<SecurityViolation>>()
        val threads = minOf(toScan.size, Runtime.getRuntime().availableProcessors().coerceAtLeast(2))
        val pool = Executors.newFixedThreadPool(threads)
        val futures = toScan.map { file ->
            pool.submit {
                try {
                    val violations = scanSingleFile(file, project, teamConfig)
                    if (violations.isNotEmpty()) parallelResults[file] = violations
                    project?.let { SafeGradleScanCache.getInstance(it).updateCache(file, violations) }
                } catch (e: Exception) {
                    e.printStackTrace()
                }
            }
        }
        futures.forEach { it.get() }
        pool.shutdown()

        results.putAll(parallelResults)
        return results
    }

    fun scanSingleFile(
        file: VirtualFile,
        project: Project?,
        teamConfig: YamlConfig?
    ): List<SecurityViolation> {
        if (!file.isValid || file.isDirectory) return emptyList()
        val content = try { String(file.contentsToByteArray()) } catch (e: Exception) { return emptyList() }

        val fileViolations = mutableListOf<SecurityViolation>()
        val settings = project?.let { SafeGradleSettings.getInstance(it).state }
        val psiFile = project?.let { proj ->
            ReadAction.compute<PsiFile?, RuntimeException> { PsiManager.getInstance(proj).findFile(file) }
        }

        for (check in checks) {
            val rawViolations = mutableListOf<SecurityViolation>()
            rawViolations.addAll(check.check(file, content, project, teamConfig))
            if (psiFile != null) {
                ReadAction.run<RuntimeException> {
                    rawViolations.addAll(check.checkPsi(psiFile, project, teamConfig))
                }
            }

            val overridden = if (teamConfig != null && teamConfig.severityOverrides.containsKey(check.id)) {
                val override = teamConfig.severityOverrides[check.id]
                if (override == null) emptyList() else rawViolations.map { it.copy(riskLevel = override) }
            } else {
                rawViolations
            }

            val filtered = overridden.filter { violation ->
                val lineContent = content.lines().getOrNull(violation.line - 1) ?: ""
                if (lineContent.contains("safegradle:ignore")) return@filter false
                if (teamConfig != null) {
                    val suppressed = teamConfig.suppressions.any { s ->
                        (s.checkId == check.id || s.checkId == "all") &&
                        file.path.endsWith(s.file) &&
                        (s.line == null || s.line == violation.line)
                    }
                    if (suppressed) return@filter false
                }
                if (settings != null) {
                    val ignored = settings.ignoredViolations.any {
                        it.filePath == file.path && it.line == violation.line && it.checkId == check.id
                    }
                    if (ignored) return@filter false
                }
                true
            }
            fileViolations.addAll(filtered)
        }
        return fileViolations
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
