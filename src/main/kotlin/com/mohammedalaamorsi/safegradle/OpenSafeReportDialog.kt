package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.components.JBScrollPane
import java.awt.BorderLayout
import java.awt.Dimension
import java.awt.event.ActionEvent
import javax.swing.*

class OpenSafeReportDialog(
    private val violations: Map<VirtualFile, List<SecurityViolation>>,
    private val projectPath: String
) : DialogWrapper(null, true) {

    init {
        title = "SafeGradle: Security Risks Detected"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout(10, 10))
        panel.preferredSize = Dimension(600, 400)

        val warningLabel = JLabel("<html><b>Warning:</b> Potential security risks were found in the build scripts of the project you are about to open.<br>Automatically running Gradle sync may compromise your system. Proceed with caution.</html>")
        warningLabel.icon = UIManager.getIcon("OptionPane.warningIcon")
        panel.add(warningLabel, BorderLayout.NORTH)

        val htmlBuilder = StringBuilder()
        htmlBuilder.append("<html><body style='font-family: sans-serif; font-size: 10px; margin: 10px;'>")
        
        violations.forEach { (file, fileViolations) ->
            htmlBuilder.append("<b>${file.path}</b><br>")
            
            fileViolations.forEach {
                val riskHtml = when (it.riskLevel) {
                    RiskLevel.HIGH -> "<font color='red'>[HIGH]</font>"
                    RiskLevel.MEDIUM -> "<font color='#FF8C00'>[MEDIUM]</font>" // Orange
                    RiskLevel.LOW -> "<font color='#D4D400'>[LOW]</font>" // Yellow
                }
                htmlBuilder.append("&nbsp;&nbsp;$riskHtml Line ${it.line}: ${it.message}<br>")
            }
            htmlBuilder.append("<br>") // spacer
        }
        htmlBuilder.append("</body></html>")

        val htmlPane = JEditorPane("text/html", htmlBuilder.toString())
        htmlPane.isEditable = false
        htmlPane.isOpaque = false // Matches IDE theme background
        
        panel.add(JBScrollPane(htmlPane), BorderLayout.CENTER)

        return panel
    }

    override fun createActions(): Array<Action> {
        val cancelAction = DialogWrapperExitAction("Cancel", CANCEL_EXIT_CODE)
        cancelAction.putValue(Action.DEFAULT, true)
        
        val proceedAction = object : DialogWrapperAction("Open Project Anyway") {
            override fun doAction(e: ActionEvent?) {
                close(OK_EXIT_CODE)
            }
        }
        
        return arrayOf(cancelAction, proceedAction)
    }
}
