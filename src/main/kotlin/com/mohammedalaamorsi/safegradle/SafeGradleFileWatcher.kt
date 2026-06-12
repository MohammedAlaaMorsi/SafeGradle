package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.newvfs.BulkFileListener
import com.intellij.openapi.vfs.newvfs.events.VFileContentChangeEvent
import com.intellij.openapi.vfs.newvfs.events.VFileEvent
import com.intellij.openapi.wm.ToolWindowManager

private val WATCHED_EXTENSIONS = setOf("gradle", "kts", "properties", "toml", "groovy")
private val WATCHED_NAMES = setOf(
    "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts",
    "gradle.properties", "gradle-wrapper.properties",
    "libs.versions.toml", ".gitignore"
)

class SafeGradleFileWatcher(private val project: Project) : BulkFileListener {

    override fun after(events: List<VFileEvent>) {
        val changed = events.filterIsInstance<VFileContentChangeEvent>().map { it.file }
        val relevant = changed.filter { file ->
            WATCHED_NAMES.contains(file.name) ||
            (file.extension?.lowercase() in WATCHED_EXTENSIONS && isUnderProject(file))
        }
        if (relevant.isEmpty()) return

        // Config and custom-check changes affect every file's results — only those need a full rescan.
        val needsFullScan = relevant.any {
            it.name == ".safegradle.yml" || it.path.contains("/.safegradle/")
        }

        ApplicationManager.getApplication().executeOnPooledThread {
            val violations = if (needsFullScan) {
                val cache = SafeGradleScanCache.getInstance(project)
                relevant.forEach { cache.invalidate(it) }
                SecurityScanner(CustomCheckLoader.loadChecks(project)).scanProject(project)
            } else {
                IncrementalScan.rescanFiles(project, relevant)
            }

            ApplicationManager.getApplication().invokeLater {
                SafeGradleResultService.getInstance(project).setResults(violations)
                if (violations.values.any { it.any { v -> v.riskLevel == RiskLevel.HIGH } }) {
                    ToolWindowManager.getInstance(project).getToolWindow("SafeGradle")?.show()
                }
            }
        }
    }

    private fun isUnderProject(file: com.intellij.openapi.vfs.VirtualFile): Boolean {
        val basePath = project.basePath ?: return false
        return file.path.startsWith(basePath)
    }
}
