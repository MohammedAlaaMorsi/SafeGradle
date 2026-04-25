package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.table.JBTable
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Dimension
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTable
import javax.swing.table.DefaultTableModel
import javax.swing.table.DefaultTableCellRenderer

class SecurityReportDialog(
    private val project: Project?,
    private val violations: Map<VirtualFile, List<SecurityViolation>>
) : DialogWrapper(project) {

    init {
        title = "Security Scan Results"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout())
        
        val totalViolations = violations.values.sumOf { it.size }
        val header = JLabel("Found $totalViolations potential security issues in ${violations.size} files. Double-click a row to navigate.")
        panel.add(header, BorderLayout.NORTH)

        val columnNames = arrayOf("File", "Line", "Risk", "Message")
        val model = object : DefaultTableModel(columnNames, 0) {
            override fun isCellEditable(row: Int, column: Int): Boolean = false
        }

        val flatViolations = mutableListOf<SecurityViolation>()
        violations.forEach { (file, list) ->
            list.forEach { violation ->
                flatViolations.add(violation)
                model.addRow(arrayOf<Any>(
                    file.name,
                    violation.line,
                    violation.riskLevel,
                    violation.message
                ))
            }
        }

        val table = JBTable(model)
        table.columnModel.getColumn(0).preferredWidth = 150
        table.columnModel.getColumn(1).preferredWidth = 50
        table.columnModel.getColumn(2).preferredWidth = 80
        table.columnModel.getColumn(3).preferredWidth = 400

        // Navigation on double click
        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && project != null) {
                    val row = table.selectedRow
                    if (row >= 0 && row < flatViolations.size) {
                        val violation = flatViolations[row]
                        val descriptor = OpenFileDescriptor(project, violation.file, violation.line - 1, 0)
                        FileEditorManager.getInstance(project).openTextEditor(descriptor, true)
                        close(OK_EXIT_CODE)
                    }
                }
            }
        })

        // Custom renderer for Risk Level (Color coding)
        table.columnModel.getColumn(2).cellRenderer = object : DefaultTableCellRenderer() {
            override fun getTableCellRendererComponent(
                table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int
            ): Component {
                val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
                if (value is RiskLevel) {
                    foreground = when (value) {
                        RiskLevel.HIGH -> Color.RED
                        RiskLevel.MEDIUM -> Color.ORANGE
                        RiskLevel.LOW -> Color.BLUE
                    }
                }
                return c
            }
        }

        val scrollPane = JBScrollPane(table)
        scrollPane.preferredSize = Dimension(800, 400)
        panel.add(scrollPane, BorderLayout.CENTER)

        return panel
    }
}
