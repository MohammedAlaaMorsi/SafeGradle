package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.fileChooser.FileChooserDescriptorFactory
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.table.JBTable
import java.awt.*
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.io.File
import javax.swing.*
import javax.swing.border.EmptyBorder
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.DefaultTableModel

class SafeGradleToolWindowFactory : ToolWindowFactory {

    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val myToolWindow = SafeGradleToolWindow(project)
        val content = ContentFactory.getInstance().createContent(myToolWindow.content, "", false)
        toolWindow.contentManager.addContent(content)
        
        val currentResults = SafeGradleResultService.getInstance(project).getResults()
        if (currentResults.isNotEmpty()) {
            myToolWindow.updateResults(currentResults)
        }
    }

    class SafeGradleToolWindow(private val project: Project) : SafeGradleResultService.ResultsListener {
        val content: JPanel = JPanel(BorderLayout())
        private val tableModel: DefaultTableModel
        private val table: JBTable
        private var flatViolations = mutableListOf<SecurityViolation>()
        private var currentViolations: Map<VirtualFile, List<SecurityViolation>> = emptyMap()
        
        private val headerLabel = JLabel("Scan a project to see results here.")
        private val exportButton = JButton("Export Results")
        
        private val summaryPanel = JPanel(FlowLayout(FlowLayout.LEFT, 20, 10))
        private val highCountLabel = JLabel("🔴 0 HIGH")
        private val mediumCountLabel = JLabel("🟠 0 MEDIUM")
        private val lowCountLabel = JLabel("🔵 0 LOW")

        init {
            project.messageBus.connect().subscribe(SafeGradleResultService.TOPIC, this)
            
            val topPanel = JPanel(BorderLayout())
            topPanel.add(headerLabel, BorderLayout.NORTH)
            headerLabel.border = EmptyBorder(10, 10, 0, 10)
            
            summaryPanel.add(highCountLabel)
            summaryPanel.add(mediumCountLabel)
            summaryPanel.add(lowCountLabel)
            
            exportButton.isVisible = false
            exportButton.addActionListener {
                val descriptor = FileChooserDescriptorFactory.createSingleFileDescriptor()
                descriptor.title = "Save Security Report"
                
                val path = Messages.showInputDialog(project, "Enter file name (e.g. report.csv):", "Export Report", null, "safegradle_report.csv", null)
                if (path != null) {
                    val file = File(project.basePath, path)
                    ReportExporter.exportToCsv(currentViolations, file)
                    Messages.showInfoMessage(project, "Report exported to ${file.absolutePath}", "Export Successful")
                }
            }
            summaryPanel.add(exportButton)
            
            summaryPanel.border = BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY)
            
            topPanel.add(summaryPanel, BorderLayout.CENTER)
            content.add(topPanel, BorderLayout.NORTH)

            val columnNames = arrayOf("File", "Line", "Risk", "Message")
            tableModel = object : DefaultTableModel(columnNames, 0) {
                override fun isCellEditable(row: Int, column: Int): Boolean = false
            }
            table = JBTable(tableModel)
            
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

            table.addMouseListener(object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    if (e.clickCount == 2) {
                        val row = table.selectedRow
                        if (row >= 0 && row < flatViolations.size) {
                            val violation = flatViolations[row]
                            val descriptor = OpenFileDescriptor(project, violation.file, violation.line - 1, 0)
                            FileEditorManager.getInstance(project).openTextEditor(descriptor, true)
                        }
                    }
                }
            })

            content.add(JBScrollPane(table), BorderLayout.CENTER)
        }

        override fun onResultsUpdated(violations: Map<VirtualFile, List<SecurityViolation>>) {
            updateResults(violations)
        }

        fun updateResults(violations: Map<VirtualFile, List<SecurityViolation>>) {
            currentViolations = violations
            tableModel.rowCount = 0
            flatViolations.clear()
            
            var high = 0
            var medium = 0
            var low = 0

            violations.forEach { (file, list) ->
                list.forEach { violation ->
                    flatViolations.add(violation)
                    tableModel.addRow(arrayOf<Any>(
                        file.name,
                        violation.line,
                        violation.riskLevel,
                        violation.message
                    ))
                    
                    when (violation.riskLevel) {
                        RiskLevel.HIGH -> high++
                        RiskLevel.MEDIUM -> medium++
                        RiskLevel.LOW -> low++
                    }
                }
            }

            val total = high + medium + low
            headerLabel.text = "Scanned ${violations.size} files. Found $total potential issues."
            highCountLabel.text = "🔴 $high HIGH"
            mediumCountLabel.text = "🟠 $medium MEDIUM"
            lowCountLabel.text = "🔵 $low LOW"
            
            highCountLabel.isVisible = high > 0
            mediumCountLabel.isVisible = medium > 0
            lowCountLabel.isVisible = low > 0
            exportButton.isVisible = total > 0
        }
    }
}
