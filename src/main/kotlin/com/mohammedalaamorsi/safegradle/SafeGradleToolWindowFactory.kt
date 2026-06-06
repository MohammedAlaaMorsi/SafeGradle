package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.fileChooser.FileChooserDescriptorFactory
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
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
import javax.swing.table.TableRowSorter

class SafeGradleToolWindowFactory : ToolWindowFactory, DumbAware {

    override fun shouldBeAvailable(project: Project): Boolean = true

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
        private lateinit var rowSorter: TableRowSorter<DefaultTableModel>
        private var flatViolations = mutableListOf<SecurityViolation>()
        private var currentViolations: Map<VirtualFile, List<SecurityViolation>> = emptyMap()

        private val headerLabel = JLabel("Scan a project to see results here.")
        private val exportButton = JButton("Export Results")
        private val saveBaselineButton = JButton("Save Baseline")
        private val newOnlyToggle = JToggleButton("New Only", false)
        private val groupByCheckToggle = JToggleButton("Group by Check", false)

        private val summaryPanel = JPanel(FlowLayout(FlowLayout.LEFT, 20, 10))
        private val highCountLabel = JLabel("🔴 0 HIGH")
        private val mediumCountLabel = JLabel("🟠 0 MEDIUM")
        private val lowCountLabel = JLabel("🔵 0 LOW")

        // Filter controls
        private val searchField = JTextField(20)
        private val showHighToggle = JToggleButton("🔴 HIGH", false)
        private val showMediumToggle = JToggleButton("🟠 MED", false)
        private val showLowToggle = JToggleButton("🔵 LOW", false)

        init {
            project.messageBus.connect().subscribe(SafeGradleResultService.TOPIC, this)

            val topPanel = JPanel(BorderLayout())
            topPanel.add(headerLabel, BorderLayout.NORTH)
            headerLabel.border = EmptyBorder(10, 10, 0, 10)

            val labelFont = headerLabel.font.deriveFont(Font.BOLD, 20f)
            highCountLabel.font = labelFont
            mediumCountLabel.font = labelFont
            lowCountLabel.font = labelFont

            highCountLabel.border = EmptyBorder(5, 5, 5, 15)
            mediumCountLabel.border = EmptyBorder(5, 5, 5, 15)
            lowCountLabel.border = EmptyBorder(5, 5, 5, 15)

            summaryPanel.add(highCountLabel)
            summaryPanel.add(mediumCountLabel)
            summaryPanel.add(lowCountLabel)

            exportButton.isVisible = false
            exportButton.font = headerLabel.font.deriveFont(Font.BOLD, 14f)
            exportButton.preferredSize = Dimension(150, 40)
            exportButton.addActionListener {
                val formats = arrayOf("CSV (.csv)", "JSON (.json)", "SARIF (.sarif) — GitHub Code Scanning")
                @Suppress("DEPRECATION")
                val choice = Messages.showChooseDialog(
                    "Choose export format:", "Export Report",
                    formats, formats[0],
                    com.intellij.icons.AllIcons.Actions.Download
                )
                if (choice >= 0) {
                    val defaultName = when (choice) {
                        1 -> "safegradle_report.json"
                        2 -> "safegradle_report.sarif"
                        else -> "safegradle_report.csv"
                    }
                    val path = Messages.showInputDialog(project, "Enter file name:", "Export Report", null, defaultName, null)
                    if (path != null) {
                        val file = File(project.basePath, path)
                        when (choice) {
                            1 -> ReportExporter.exportToJson(currentViolations, file)
                            2 -> ReportExporter.exportToSarif(currentViolations, file)
                            else -> ReportExporter.exportToCsv(currentViolations, file)
                        }
                        Messages.showInfoMessage(project, "Report exported to ${file.absolutePath}", "Export Successful")
                    }
                }
            }
            summaryPanel.add(exportButton)

            saveBaselineButton.isVisible = false
            saveBaselineButton.toolTipText = "Save current results as baseline — only NEW violations will be shown on future scans"
            saveBaselineButton.addActionListener {
                SafeGradleBaseline.save(currentViolations, project)
                Messages.showInfoMessage(project, ".safegradle-baseline.json saved. Future scans will only show new findings.", "Baseline Saved")
                applyFilter()
            }
            summaryPanel.add(saveBaselineButton)

            newOnlyToggle.isVisible = false
            newOnlyToggle.toolTipText = "When enabled, only violations absent from the saved baseline are shown"
            newOnlyToggle.addActionListener { applyFilter() }
            summaryPanel.add(newOnlyToggle)

            groupByCheckToggle.toolTipText = "Toggle between grouping results by file (default) or by check type"
            groupByCheckToggle.addActionListener { rebuildTable() }
            summaryPanel.add(groupByCheckToggle)

            summaryPanel.border = BorderFactory.createMatteBorder(0, 0, 1, 0, Color.GRAY)
            topPanel.add(summaryPanel, BorderLayout.CENTER)

            // Filter bar
            val filterPanel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
            filterPanel.add(JLabel("Filter:"))
            filterPanel.add(searchField)
            filterPanel.add(showHighToggle)
            filterPanel.add(showMediumToggle)
            filterPanel.add(showLowToggle)
            filterPanel.border = BorderFactory.createMatteBorder(0, 0, 1, 0, Color.LIGHT_GRAY)

            val filterListener = { _: Any -> applyFilter() }
            searchField.document.addDocumentListener(object : javax.swing.event.DocumentListener {
                override fun insertUpdate(e: javax.swing.event.DocumentEvent) = filterListener(e)
                override fun removeUpdate(e: javax.swing.event.DocumentEvent) = filterListener(e)
                override fun changedUpdate(e: javax.swing.event.DocumentEvent) = filterListener(e)
            })
            showHighToggle.addActionListener { applyFilter() }
            showMediumToggle.addActionListener { applyFilter() }
            showLowToggle.addActionListener { applyFilter() }

            val northWrapper = JPanel(BorderLayout())
            northWrapper.add(topPanel, BorderLayout.NORTH)
            northWrapper.add(filterPanel, BorderLayout.SOUTH)
            content.add(northWrapper, BorderLayout.NORTH)

            val columnNames = arrayOf("File", "Line", "Risk", "Message")
            tableModel = object : DefaultTableModel(columnNames, 0) {
                override fun isCellEditable(row: Int, column: Int): Boolean = false
            }
            table = JBTable(tableModel)
            rowSorter = TableRowSorter(tableModel)
            table.rowSorter = rowSorter

            table.columnModel.getColumn(2).cellRenderer = object : DefaultTableCellRenderer() {
                override fun getTableCellRendererComponent(
                    table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int
                ): Component {
                    val c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
                    if (value is RiskLevel) {
                        foreground = when (value) {
                            RiskLevel.HIGH -> Color.RED
                            RiskLevel.MEDIUM -> Color.ORANGE
                            RiskLevel.LOW -> Color(130, 130, 130)
                        }
                    }
                    return c
                }
            }

            table.addMouseListener(object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    if (e.clickCount == 2) {
                        val modelRow = table.convertRowIndexToModel(table.selectedRow)
                        if (modelRow >= 0 && modelRow < flatViolations.size) {
                            val violation = flatViolations[modelRow]
                            val descriptor = OpenFileDescriptor(project, violation.file, violation.line - 1, 0)
                            FileEditorManager.getInstance(project).openTextEditor(descriptor, true)
                        }
                    }
                }
            })

            // Detail panel — shows full message + remediation for the selected row
            val detailArea = JBTextArea(5, 80).apply {
                isEditable = false
                lineWrap = true
                wrapStyleWord = true
                font = font.deriveFont(12f)
                border = EmptyBorder(8, 8, 8, 8)
            }
            val detailScroll = JBScrollPane(detailArea).apply {
                border = BorderFactory.createMatteBorder(1, 0, 0, 0, Color.LIGHT_GRAY)
                minimumSize = Dimension(0, 80)
                preferredSize = Dimension(0, 110)
            }

            table.selectionModel.addListSelectionListener {
                val modelRow = if (table.selectedRow >= 0) table.convertRowIndexToModel(table.selectedRow) else -1
                val violation = flatViolations.getOrNull(modelRow)
                if (violation != null) {
                    val check = SecurityScanner().let { s ->
                        // Find the check by matching its id to the violation's checkId
                        null // description lookup is in the check classes; embed it in the violation message
                    }
                    detailArea.text = buildString {
                        append("[${violation.riskLevel}] ${violation.file.name}:${violation.line}\n\n")
                        append(violation.message)
                        append("\n\n")
                        append("Code: ${violation.content.take(200)}")
                    }
                    detailArea.caretPosition = 0
                } else {
                    detailArea.text = ""
                }
            }

            val splitPane = javax.swing.JSplitPane(
                javax.swing.JSplitPane.VERTICAL_SPLIT,
                JBScrollPane(table),
                detailScroll
            ).apply {
                resizeWeight = 0.75
                isContinuousLayout = true
            }
            content.add(splitPane, BorderLayout.CENTER)
        }

        private fun applyFilter() {
            val baseline = if (newOnlyToggle.isSelected) SafeGradleBaseline.load(project) else emptySet()
            val text = searchField.text.trim().lowercase()
            val highOn = showHighToggle.isSelected
            val medOn  = showMediumToggle.isSelected
            val lowOn  = showLowToggle.isSelected
            val anyOn  = highOn || medOn || lowOn

            rowSorter.rowFilter = object : RowFilter<DefaultTableModel, Int>() {
                override fun include(entry: Entry<out DefaultTableModel, out Int>): Boolean {
                    // Risk-level filter: read directly from column 2 (the RiskLevel object),
                    // so this never depends on flatViolations ordering.
                    if (anyOn) {
                        val risk = entry.getValue(2) as? RiskLevel
                        val pass = (highOn && risk == RiskLevel.HIGH) ||
                                   (medOn  && risk == RiskLevel.MEDIUM) ||
                                   (lowOn  && risk == RiskLevel.LOW)
                        if (!pass) return false
                    }

                    // Baseline filter
                    if (baseline.isNotEmpty()) {
                        val violation = flatViolations.getOrNull(entry.identifier) ?: return false
                        if (!SafeGradleBaseline.isNew(violation, baseline)) return false
                    }

                    // Text search
                    if (text.isNotEmpty()) {
                        val row = (0 until entry.valueCount)
                            .joinToString(" ") { entry.getStringValue(it) }
                            .lowercase()
                        if (!row.contains(text)) return false
                    }

                    return true
                }
            }
        }

        override fun onResultsUpdated(violations: Map<VirtualFile, List<SecurityViolation>>) {
            updateResults(violations)
        }

        private fun rebuildTable() {
            tableModel.setColumnIdentifiers(
                if (groupByCheckToggle.isSelected) arrayOf("Check", "Line", "Risk", "Message")
                else arrayOf("File", "Line", "Risk", "Message")
            )
            tableModel.rowCount = 0
            flatViolations.clear()
            val orderedViolations = if (groupByCheckToggle.isSelected) {
                currentViolations.values.flatten()
                    .sortedWith(compareBy({ it.checkId }, { it.riskLevel.ordinal.unaryMinus() }))
            } else {
                currentViolations.entries.flatMap { (_, list) -> list }
            }
            orderedViolations.forEach { v ->
                flatViolations.add(v)
                val label = if (groupByCheckToggle.isSelected) v.checkId else v.file.name
                tableModel.addRow(arrayOf<Any>(label, v.line, v.riskLevel, v.message))
            }
            applyFilter()
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
            saveBaselineButton.isVisible = total > 0
            newOnlyToggle.isVisible = SafeGradleBaseline.exists(project)

            // Record snapshot and update trend in header
            SafeGradleScanHistory.getInstance(project).record(high, medium, low)
            val snapshots = SafeGradleScanHistory.getInstance(project).snapshots()
            if (snapshots.size > 1) {
                val trend = snapshots.takeLast(5).joinToString(" → ") { s ->
                    val t = s.high + s.medium + s.low
                    if (s.high > 0) "🔴$t" else if (s.medium > 0) "🟠$t" else "🔵$t"
                }
                headerLabel.text = "Scanned ${violations.size} files. Found $total issues.  Trend: $trend"
            } else {
                headerLabel.text = "Scanned ${violations.size} files. Found $total potential issues."
            }

            applyFilter()
        }
    }
}
