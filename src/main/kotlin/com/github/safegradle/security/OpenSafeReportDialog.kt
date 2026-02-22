package com.github.safegradle.security

import com.intellij.ide.impl.ProjectUtil
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import java.awt.BorderLayout
import java.awt.Dimension
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

        val listModel = DefaultListModel<String>()
        violations.forEach { (file, fileViolations) ->
            listModel.addElement("<html><b>${file.path}</b></html>")
            fileViolations.forEach {
                val riskHtml = when (it.riskLevel) {
                    RiskLevel.HIGH -> "<font color='red'>[HIGH]</font>"
                    RiskLevel.MEDIUM -> "<font color='orange'>[MEDIUM]</font>"
                    RiskLevel.LOW -> "<font color='yellow'>[LOW]</font>"
                }
                listModel.addElement("  $riskHtml Line ${it.line}: ${it.message}")
            }
            listModel.addElement(" ") // spacer
        }

        val list = JBList(listModel)
        list.selectionMode = ListSelectionModel.SINGLE_SELECTION
        panel.add(JBScrollPane(list), BorderLayout.CENTER)

        return panel
    }

    override fun createActions(): Array<Action> {
        val cancelAction = DialogWrapperExitAction("Cancel Open", CANCEL_EXIT_CODE)
        cancelAction.putValue(Action.DEFAULT, true)
        
        val proceedAction = object : DialogWrapperAction("Open Project Anyway") {
            override fun doAction(e: java.awt.event.ActionEvent?) {
                close(OK_EXIT_CODE)
                ProjectUtil.openOrImport(projectPath, null, true)
            }
        }
        
        return arrayOf(cancelAction, proceedAction)
    }
}
