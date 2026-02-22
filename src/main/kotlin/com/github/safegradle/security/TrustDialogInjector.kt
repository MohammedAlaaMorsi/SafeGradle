package com.github.safegradle.security

import com.intellij.ide.AppLifecycleListener
import com.intellij.openapi.application.ApplicationManager
import java.awt.AWTEvent
import java.awt.Container
import java.awt.Toolkit
import java.awt.Window
import java.awt.event.AWTEventListener
import java.awt.event.WindowEvent
import javax.swing.JButton
import javax.swing.JPanel
import javax.swing.SwingUtilities
import javax.swing.Timer

class TrustDialogInjector : AppLifecycleListener {

    private val listener = AWTEventListener { event ->
        if (event is WindowEvent && event.id == WindowEvent.WINDOW_OPENED) {
            val window = event.window
            // We no longer restrict by title or JDialog. JetBrains completely customizes their dialogs.
            // We will scan ANY window that opens for the "Trust Project" button.
            injectButtonIntoWindow(window)
        }
    }

    override fun appStarted() {
        Toolkit.getDefaultToolkit().addAWTEventListener(listener, AWTEvent.WINDOW_EVENT_MASK)
    }

    override fun appFrameCreated(commandLineArgs: MutableList<String>) {
        Toolkit.getDefaultToolkit().removeAWTEventListener(listener)
        Toolkit.getDefaultToolkit().addAWTEventListener(listener, AWTEvent.WINDOW_EVENT_MASK)
    }

    private fun injectButtonIntoWindow(window: Window) {
        // Use a timer to poll for the UI components in case they render late
        // Try every 100ms for up to 3 seconds.
        val timer = Timer(100, null)
        var attempts = 0
        
        timer.addActionListener {
            attempts++
            if (attempts > 30) {
                timer.stop()
                return@addActionListener
            }

            val buttonsPanel = findButtonPanel(window)
            if (buttonsPanel != null) {
                timer.stop() // Found it!

                val alreadyInjected = buttonsPanel.components.any { it is JButton && it.text == "Open in SafeGradle" }
                if (!alreadyInjected) {
                    val safeButton = JButton("Open in SafeGradle")
                    
                    safeButton.addActionListener {
                        val trustButton = buttonsPanel.components.firstOrNull { it is JButton && (it.text?.contains("Trust", ignoreCase = true) == true) } as? JButton
                        val cancelButton = buttonsPanel.components.firstOrNull { it is JButton && (it.text?.contains("Don't Open", ignoreCase = true) == true || it.text?.contains("Cancel", ignoreCase = true) == true) } as? JButton
                        
                        // Try to find the exact project path
                        var projectPath: String? = null
                        val title = (window as? javax.swing.JDialog)?.title ?: (window as? javax.swing.JFrame)?.title ?: ""
                        val projectNameMatch = Regex("'([^']+)'").find(title)
                        val projectName = projectNameMatch?.groupValues?.get(1)

                        // 1. Try Recent Projects
                        try {
                            if (projectName != null) {
                                val recentManager = com.intellij.ide.RecentProjectsManager.getInstance()
                                if (recentManager != null) {
                                    // recentManager.recentPaths is sometimes a list, sometimes unavailable depending on IntelliJ version.
                                    // Use reflection to be safe since it's an internal class anyway.
                                    val method = recentManager.javaClass.getMethod("getRecentPaths")
                                    val paths = method.invoke(recentManager) as? List<*>
                                    projectPath = paths?.firstOrNull { it is String && (it.endsWith("/$projectName") || it.endsWith("\\$projectName")) } as? String
                                }
                            }
                        } catch (e: Exception) {}

                        // 2. Try Open Projects
                        try {
                            if (projectPath == null && projectName != null) {
                                val openProjects = com.intellij.openapi.project.ProjectManager.getInstance().openProjects
                                projectPath = openProjects.firstOrNull { it.name == projectName }?.basePath
                            }
                        } catch (e: Exception) {}

                        // 3. Try Reflection on DialogWrapper
                        try {
                            if (projectPath == null) {
                                val wrapper = com.intellij.openapi.ui.DialogWrapper.findInstance(window)
                                if (wrapper != null) {
                                    for (field in wrapper.javaClass.declaredFields) {
                                        field.isAccessible = true
                                        val value = field.get(wrapper)
                                        if (value is com.intellij.openapi.project.Project) { projectPath = value.basePath; break }
                                        if (value is java.nio.file.Path) { projectPath = value.toAbsolutePath().toString(); break }
                                        if (value is java.io.File) { projectPath = value.absolutePath; break }
                                        if (value is com.intellij.openapi.vfs.VirtualFile) { projectPath = value.path; break }
                                        if (value is String && (value.endsWith("/$projectName") || value.endsWith("\\$projectName"))) { projectPath = value; break }
                                    }
                                }
                            }
                        } catch (e: Exception) {}

                        if (projectPath != null) {
                            val vFile = com.intellij.openapi.vfs.LocalFileSystem.getInstance().findFileByPath(projectPath!!)
                            if (vFile != null) {
                                com.intellij.openapi.progress.ProgressManager.getInstance().run(
                                    object : com.intellij.openapi.progress.Task.Modal(null, "Scanning build scripts...", true) {
                                        override fun run(indicator: com.intellij.openapi.progress.ProgressIndicator) {
                                            val scanner = SecurityScanner()
                                            val violations = scanner.scanDirectory(vFile)
                                            
                                            SwingUtilities.invokeLater {
                                                if (violations.isEmpty()) {
                                                    trustButton?.doClick() ?: window.dispose()
                                                } else {
                                                    val dialog = OpenSafeReportDialog(violations, projectPath!!)
                                                    if (dialog.showAndGet()) {
                                                        // "Open Project Anyway" was clicked
                                                        trustButton?.doClick() ?: window.dispose()
                                                    } else {
                                                        // "Cancel" was clicked
                                                        cancelButton?.doClick() ?: window.dispose()
                                                    }
                                                }
                                            }
                                        }
                                    }
                                )
                                return@addActionListener
                            }
                        }

                        // Fallback if we couldn't resolve the path
                        window.dispose()
                        val action = OpenSafeProjectAction()
                        val event = com.intellij.openapi.actionSystem.AnActionEvent.createFromAnAction(
                            action, null, "TrustDialogInjector", com.intellij.openapi.actionSystem.DataContext.EMPTY_CONTEXT
                        )
                        action.actionPerformed(event)
                    }

                    buttonsPanel.add(safeButton, 0)
                    buttonsPanel.revalidate()
                    buttonsPanel.repaint()
                    
                    // Expand the window slightly
                    window.setSize(window.width + 180, window.height)
                }
            }
        }
        timer.start()
    }

    // Breadth-first search for the JPanel containing the "Trust Project" button
    private fun findButtonPanel(container: Container): JPanel? {
        val queue = java.util.LinkedList<Container>()
        queue.add(container)

        while (queue.isNotEmpty()) {
            val curr = queue.poll()

            if (curr is JPanel) {
                val buttons = curr.components.filterIsInstance<JButton>()
                if (buttons.isNotEmpty()) {
                    val hasTargetButton = buttons.any { button ->
                        val text = button.text?.replace("&", "")?.replace("_", "") ?: ""
                        text.contains("Trust Project", ignoreCase = true) || 
                        text.contains("Preview in Safe Mode", ignoreCase = true)
                    }

                    if (hasTargetButton) {
                        return curr
                    }
                }
            }

            for (component in curr.components) {
                if (component is Container) {
                    queue.add(component)
                }
            }
        }
        return null
    }
}
