package com.github.safegradle.security

import com.intellij.ide.impl.ProjectUtil
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.fileChooser.FileChooserDescriptorFactory
import com.intellij.openapi.fileChooser.FileChooser
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task

class OpenSafeProjectAction : AnAction() {
    override fun actionPerformed(e: AnActionEvent) {
        val descriptor = FileChooserDescriptorFactory.createSingleFolderDescriptor()
        descriptor.title = "Select Project to Open Safely"
        
        FileChooser.chooseFile(descriptor, e.project, null) { file ->
            if (file != null && file.isDirectory) {
                // Run background task so UI doesn't freeze
                ProgressManager.getInstance().run(object : Task.Modal(null, "SafeGradle: Scanning Project Folder", true) {
                    override fun run(indicator: ProgressIndicator) {
                        indicator.text = "Scanning build scripts for malicious code..."
                        
                        val scanner = SecurityScanner()
                        val violations = scanner.scanDirectory(file)
                        
                        ApplicationManager.getApplication().invokeLater {
                            if (violations.isEmpty()) {
                                // Safe, just open it
                                ProjectUtil.openOrImport(file.path, null, true)
                            } else {
                                // Risks found! Ask user
                                // We'll leverage the SecurityReportDialog, but tweak its behavior for this flow
                                val dialog = OpenSafeReportDialog(violations, file.path)
                                dialog.show()
                            }
                        }
                    }
                })
            }
        }
    }
}
