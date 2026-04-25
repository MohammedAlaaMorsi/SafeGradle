package com.mohammedalaamorsi.safegradle

import com.intellij.ide.AppLifecycleListener
import com.intellij.ide.DataManager
import com.intellij.ide.RecentProjectsManager
import com.intellij.openapi.actionSystem.ActionUiKind
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.ex.ActionUtil
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.ProjectManager
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VirtualFile
import java.awt.AWTEvent
import java.awt.Container
import java.awt.Toolkit
import java.awt.Window
import java.awt.event.AWTEventListener
import java.awt.event.WindowEvent
import java.io.File
import java.nio.file.Path
import java.util.LinkedList
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JFrame
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
                        val title = (window as? JDialog)?.title ?: (window as? JFrame)?.title ?: ""
                        val projectNameMatch = Regex("'([^']+)'").find(title)
                        val projectName = projectNameMatch?.groupValues?.get(1)

                        // 1. Try Recent Projects
                        try {
                            projectName?.let { pName ->
                                val recentManager = RecentProjectsManager.getInstance()
                                    val method = recentManager.javaClass.getMethod("getRecentPaths")
                                    val paths = method.invoke(recentManager) as? List<*>
                                    projectPath = paths?.firstOrNull { it is String && (it.endsWith("/$pName") || it.endsWith("\\$pName")) } as? String
                            }
                        } catch (e: Exception) {}

                        // 2. Try Open Projects
                        try {
                            if (projectPath == null && projectName != null) {
                                val openProjects = ProjectManager.getInstance().openProjects
                                projectPath = openProjects.firstOrNull { it.name == projectName }?.basePath
                            }
                        } catch (e: Exception) {}

                        // 3. Try Reflection on DialogWrapper
                        try {
                            if (projectPath == null) {
                                val wrapper = DialogWrapper.findInstance(window)
                                if (wrapper != null) {
                                    for (field in wrapper.javaClass.declaredFields) {
                                        field.isAccessible = true
                                        val value = field.get(wrapper)
                                        if (value is Project) { projectPath = value.basePath; break }
                                        if (value is Path) { projectPath = value.toAbsolutePath().toString(); break }
                                        if (value is File) { projectPath = value.absolutePath; break }
                                        if (value is VirtualFile) { projectPath = value.path; break }
                                        if (value is String && (value.endsWith("/$projectName") || value.endsWith("\\$projectName"))) { projectPath = value; break }
                                    }
                                }
                            }
                        } catch (e: Exception) {}

                        if (projectPath != null) {
                            val vFile = LocalFileSystem.getInstance().findFileByPath(projectPath!!)
                            if (vFile != null) {
                                ProgressManager.getInstance().run(
                                    object : Task.Modal(null, "Scanning build scripts...", true) {
                                        override fun run(indicator: ProgressIndicator) {
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
                        val context = DataManager.getInstance().getDataContext(window)
                        ActionUtil.invokeAction(action, context, "TrustDialogInjector", null, null)
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
        val queue = LinkedList<Container>()
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
