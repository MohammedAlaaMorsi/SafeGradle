package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.startup.ProjectActivity
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.wm.ToolWindowManager

class SafeGradleProjectOpenListener : ProjectActivity {
    override suspend fun execute(project: Project) {
        // Run a lightweight scan in the background
        ApplicationManager.getApplication().executeOnPooledThread {
            val scanner = SecurityScanner()
            val violations = scanner.scanProject(project)
            
            ApplicationManager.getApplication().invokeLater {
                SafeGradleResultService.getInstance(project).setResults(violations)
                
                // If there are high risk violations, show the tool window
                if (violations.values.any { it.any { v -> v.riskLevel == RiskLevel.HIGH } }) {
                    val toolWindow = ToolWindowManager.getInstance(project).getToolWindow("SafeGradle")
                    toolWindow?.show()
                }
            }
        }
    }
}
