package com.mohammedalaamorsi.safegradle

import com.intellij.notification.NotificationAction
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskId
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskNotificationListener
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskType
import com.intellij.openapi.wm.ToolWindowManager

/**
 * Pre-sync execution guard that audits Gradle build scripts right before the Gradle daemon
 * executes the configuration phase (sync/resolve), protecting against malicious script execution.
 * Also performs an automatic rescan upon successful sync completion to keep results fresh.
 */
class SafeGradleSyncListener : ExternalSystemTaskNotificationListener {

    override fun onStart(id: ExternalSystemTaskId, workingDir: String?) {
        if (id.projectSystemId.id != "GRADLE") return
        if (id.type != ExternalSystemTaskType.RESOLVE_PROJECT) return

        val project = id.findProject() ?: return

        // Fast pre-sync check across project build scripts
        val customChecks = CustomCheckLoader.loadChecks(project)
        val scanner = SecurityScanner(customChecks)
        val violations = scanner.scanProject(project)

        val highRiskViolations = violations.values.flatten().filter { it.riskLevel == RiskLevel.HIGH }
        if (highRiskViolations.isNotEmpty()) {
            ApplicationManager.getApplication().invokeLater {
                SafeGradleResultService.getInstance(project).setResults(violations)

                val count = highRiskViolations.size
                val notification = NotificationGroupManager.getInstance()
                    .getNotificationGroup("Security Scan Results")
                    .createNotification(
                        "SafeGradle Sync Guard: $count High-Risk Threat${if (count == 1) "" else "s"} Detected",
                        "Untrusted code execution may occur during Gradle sync. Review high-severity findings immediately.",
                        NotificationType.WARNING
                    )

                notification.addAction(NotificationAction.createSimpleExpiring("View Findings in SafeGradle") {
                    ToolWindowManager.getInstance(project).getToolWindow("SafeGradle")?.show()
                })

                notification.notify(project)
            }
        }
    }

    override fun onSuccess(id: ExternalSystemTaskId) {
        if (id.projectSystemId.id != "GRADLE") return
        if (id.type != ExternalSystemTaskType.RESOLVE_PROJECT) return

        val project = id.findProject() ?: return

        // Automatically update scan results after sync completes
        ApplicationManager.getApplication().executeOnPooledThread {
            val customChecks = CustomCheckLoader.loadChecks(project)
            val scanner = SecurityScanner(customChecks)
            val violations = scanner.scanProject(project)
            ApplicationManager.getApplication().invokeLater {
                SafeGradleResultService.getInstance(project).setResults(violations)
            }
        }
    }
}
