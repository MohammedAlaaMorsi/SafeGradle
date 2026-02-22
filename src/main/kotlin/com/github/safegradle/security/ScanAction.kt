package com.github.safegradle.security

import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.application.ApplicationManager

class ScanAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        ProgressManager.getInstance().run(object : Task.Modal(project, "Scanning for Security Risks", true) {
            override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                indicator.text = "Scanning build scripts..."
                
                val scanner = SecurityScanner()
                val violations = scanner.scanProject(project)

                ApplicationManager.getApplication().invokeLater {
                    if (violations.isEmpty()) {
                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("Security Scan Results") // Make sure to define this in plugin.xml or use default
                            .createNotification("No security risks found in build scripts.", NotificationType.INFORMATION)
                            .notify(project)
                    } else {
                        SecurityReportDialog(project, violations).show()
                    }
                }
            }
        })
    }
}
