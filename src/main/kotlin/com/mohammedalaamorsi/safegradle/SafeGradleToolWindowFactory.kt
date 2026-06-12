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
import java.awt.datatransfer.StringSelection
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

            // The summary labels double as clickable filter chips, kept in sync with the toggles below.
            makeSeverityChip(highCountLabel, showHighToggle)
            makeSeverityChip(mediumCountLabel, showMediumToggle)
            makeSeverityChip(lowCountLabel, showLowToggle)

            summaryPanel.add(highCountLabel)
            summaryPanel.add(mediumCountLabel)
            summaryPanel.add(lowCountLabel)

            exportButton.isVisible = false
            exportButton.font = headerLabel.font.deriveFont(Font.BOLD, 14f)
            exportButton.preferredSize = Dimension(150, 40)
            exportButton.addActionListener {
                val formats = arrayOf("CSV (.csv)", "JSON (.json)", "SARIF (.sarif) — GitHub Code Scanning", "HTML (.html) — shareable report")
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
                        3 -> "safegradle_report.html"
                        else -> "safegradle_report.csv"
                    }
                    val path = Messages.showInputDialog(project, "Enter file name:", "Export Report", null, defaultName, null)
                    if (path != null) {
                        val file = File(project.basePath, path)
                        when (choice) {
                            1 -> ReportExporter.exportToJson(currentViolations, file)
                            2 -> ReportExporter.exportToSarif(currentViolations, file)
                            3 -> ReportExporter.exportToHtml(currentViolations, file)
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
                // Correct column classes so the sorter compares lines numerically
                // and risk by severity (enum order LOW < MEDIUM < HIGH) instead of by toString().
                override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
                    1 -> java.lang.Integer::class.java
                    2 -> RiskLevel::class.java
                    else -> String::class.java
                }
            }
            table = JBTable(tableModel)
            rowSorter = TableRowSorter(tableModel)
            table.rowSorter = rowSorter
            installRiskRenderer()

            table.addMouseListener(object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    if (e.clickCount == 2) {
                        openSelectedViolation()
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

            table.selectionModel.addListSelectionListener { e ->
                if (e.valueIsAdjusting) return@addListSelectionListener
                val violation = selectedViolation()
                if (violation != null) {
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

            installContextMenu()

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
            val text = searchField.text
            val highOn = showHighToggle.isSelected
            val medOn  = showMediumToggle.isSelected
            val lowOn  = showLowToggle.isSelected

            syncSeverityChips()

            rowSorter.rowFilter = object : RowFilter<DefaultTableModel, Int>() {
                override fun include(entry: Entry<out DefaultTableModel, out Int>): Boolean {
                    val risk = entry.getValue(2) as? RiskLevel
                    val rowText = (0 until entry.valueCount).joinToString(" ") { entry.getStringValue(it) }
                    if (!ViolationRowMatcher.matches(risk, highOn, medOn, lowOn, text, rowText)) return false

                    // Baseline filter
                    if (baseline.isNotEmpty()) {
                        val violation = flatViolations.getOrNull(entry.identifier) ?: return false
                        if (!SafeGradleBaseline.isNew(violation, baseline)) return false
                    }

                    return true
                }
            }
        }

        /** Keeps the big severity chips visually in sync with the toggle buttons. */
        private fun syncSeverityChips() {
            for ((label, toggle) in listOf(
                highCountLabel to showHighToggle,
                mediumCountLabel to showMediumToggle,
                lowCountLabel to showLowToggle
            )) {
                label.isOpaque = toggle.isSelected
                label.background = if (toggle.isSelected) UIManager.getColor("List.selectionBackground") else null
                label.repaint()
            }
        }

        /** Makes a summary count label act as a clickable filter chip bound to [toggle]. */
        private fun makeSeverityChip(label: JLabel, toggle: JToggleButton) {
            label.border = EmptyBorder(5, 5, 5, 15)
            label.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
            label.toolTipText = "Click to show only these violations; click again to clear"
            label.addMouseListener(object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    toggle.isSelected = !toggle.isSelected
                    applyFilter()
                }
            })
        }

        /** Re-installs the Risk column renderer; needed after every table structure change. */
        private fun installRiskRenderer() {
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
        }

        private fun selectedViolation(): SecurityViolation? {
            val viewRow = table.selectedRow
            if (viewRow < 0) return null
            return flatViolations.getOrNull(table.convertRowIndexToModel(viewRow))
        }

        private fun openSelectedViolation() {
            val violation = selectedViolation() ?: return
            val descriptor = OpenFileDescriptor(project, violation.file, violation.line - 1, 0)
            FileEditorManager.getInstance(project).openTextEditor(descriptor, true)
        }

        /** Right-click menu on result rows: navigate, copy details, upgrade, suppress. */
        private fun installContextMenu() {
            val menu = JPopupMenu()
            menu.add(JMenuItem("Jump to Source").apply {
                addActionListener { openSelectedViolation() }
            })
            val upgradeItem = JMenuItem("Upgrade to Fixed Version").apply {
                addActionListener { upgradeSelectedViolation() }
            }
            menu.add(upgradeItem)
            menu.addPopupMenuListener(object : javax.swing.event.PopupMenuListener {
                override fun popupMenuWillBecomeVisible(e: javax.swing.event.PopupMenuEvent) {
                    val fix = selectedViolation()?.fixVersion
                    upgradeItem.isEnabled = fix != null
                    upgradeItem.text = if (fix != null) "Upgrade to Fixed Version ($fix)" else "Upgrade to Fixed Version"
                }
                override fun popupMenuWillBecomeInvisible(e: javax.swing.event.PopupMenuEvent) {}
                override fun popupMenuCanceled(e: javax.swing.event.PopupMenuEvent) {}
            })
            menu.add(JMenuItem("Copy Violation Details").apply {
                addActionListener {
                    val v = selectedViolation() ?: return@addActionListener
                    val details = "[${v.riskLevel}] ${v.file.path}:${v.line} — ${v.message}\n${v.content}"
                    Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(details), null)
                }
            })
            menu.add(JMenuItem("Suppress (add // safegradle:ignore)").apply {
                addActionListener { suppressSelectedViolation() }
            })
            table.componentPopupMenu = menu
            // Make right-click select the row under the cursor before the menu opens.
            table.addMouseListener(object : MouseAdapter() {
                override fun mousePressed(e: MouseEvent) {
                    if (SwingUtilities.isRightMouseButton(e)) {
                        val row = table.rowAtPoint(e.point)
                        if (row >= 0) table.setRowSelectionInterval(row, row)
                    }
                }
            })
        }

        /** Rewrites the dependency's version to the known fixed version, saves, and rescans the file. */
        private fun upgradeSelectedViolation() {
            val violation = selectedViolation() ?: return
            val fix = violation.fixVersion ?: return
            val fileDocManager = com.intellij.openapi.fileEditor.FileDocumentManager.getInstance()
            val document = fileDocManager.getDocument(violation.file) ?: return
            val lineIndex = violation.line - 1
            if (lineIndex < 0 || lineIndex >= document.lineCount) return
            val start = document.getLineStartOffset(lineIndex)
            val end = document.getLineEndOffset(lineIndex)
            val upgraded = DependencyUpgrader.upgradeLine(document.getText(com.intellij.openapi.util.TextRange(start, end)), fix)
            if (upgraded == null) {
                Messages.showInfoMessage(
                    project,
                    "This dependency uses an indirect or interpolated version — update it manually to $fix.",
                    "Cannot Upgrade Automatically"
                )
                return
            }
            com.intellij.openapi.command.WriteCommandAction.runWriteCommandAction(project) {
                document.replaceString(start, end, upgraded)
                fileDocManager.saveDocument(document)
            }
            com.intellij.openapi.application.ApplicationManager.getApplication().executeOnPooledThread {
                val merged = IncrementalScan.rescanFiles(project, listOf(violation.file))
                com.intellij.openapi.application.ApplicationManager.getApplication().invokeLater {
                    SafeGradleResultService.getInstance(project).setResults(merged)
                }
            }
        }

        /** Appends `// safegradle:ignore` to the violation's line and rescans that file's row out of view. */
        private fun suppressSelectedViolation() {
            val violation = selectedViolation() ?: return
            val document = com.intellij.openapi.fileEditor.FileDocumentManager.getInstance()
                .getDocument(violation.file) ?: return
            val lineIndex = violation.line - 1
            if (lineIndex < 0 || lineIndex >= document.lineCount) return
            val lineEnd = document.getLineEndOffset(lineIndex)
            val lineText = document.getText(
                com.intellij.openapi.util.TextRange(document.getLineStartOffset(lineIndex), lineEnd)
            )
            if (lineText.contains("safegradle:ignore")) return
            com.intellij.openapi.command.WriteCommandAction.runWriteCommandAction(project) {
                document.insertString(lineEnd, " // safegradle:ignore")
            }
            // Drop the suppressed violation from the current view immediately.
            val updated = currentViolations.mapValues { (_, list) -> list.filterNot { it === violation } }
                .filterValues { it.isNotEmpty() }
            SafeGradleResultService.getInstance(project).setResults(updated)
        }

        override fun onResultsUpdated(violations: Map<VirtualFile, List<SecurityViolation>>) {
            updateResults(violations)
        }

        private fun rebuildTable() {
            // setColumnIdentifiers fires a structure change: JTable recreates its columns,
            // dropping the Risk renderer and the sort keys — both must be restored afterwards.
            tableModel.setColumnIdentifiers(
                if (groupByCheckToggle.isSelected) arrayOf("Check", "Line", "Risk", "Message")
                else arrayOf("File", "Line", "Risk", "Message")
            )
            installRiskRenderer()
            rowSorter.sortKeys = listOf(RowSorter.SortKey(2, SortOrder.DESCENDING))

            tableModel.rowCount = 0
            flatViolations.clear()
            val orderedViolations = if (groupByCheckToggle.isSelected) {
                currentViolations.values.flatten()
                    .sortedWith(compareBy({ it.checkId }, { -it.riskLevel.ordinal }))
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
            rebuildTable()

            val all = violations.values.flatten()
            val high = all.count { it.riskLevel == RiskLevel.HIGH }
            val medium = all.count { it.riskLevel == RiskLevel.MEDIUM }
            val low = all.count { it.riskLevel == RiskLevel.LOW }
            val total = high + medium + low
            highCountLabel.text = "🔴 $high HIGH"
            mediumCountLabel.text = "🟠 $medium MEDIUM"
            lowCountLabel.text = "🔵 $low LOW"
            
            highCountLabel.isVisible = high > 0
            mediumCountLabel.isVisible = medium > 0
            lowCountLabel.isVisible = low > 0
            exportButton.isVisible = total > 0
            saveBaselineButton.isVisible = total > 0
            newOnlyToggle.isVisible = SafeGradleBaseline.exists(project)

            // Record snapshot and update grade + trend in header
            val grade = SecurityScore.grade(high, medium, low)
            headerLabel.toolTipText = SecurityScore.FORMULA
            SafeGradleScanHistory.getInstance(project).record(high, medium, low)
            val snapshots = SafeGradleScanHistory.getInstance(project).snapshots()
            if (snapshots.size > 1) {
                val trend = snapshots.takeLast(5).joinToString(" → ") { s ->
                    val t = s.high + s.medium + s.low
                    if (s.high > 0) "🔴$t" else if (s.medium > 0) "🟠$t" else "🔵$t"
                }
                headerLabel.text = "Security Grade: $grade — scanned ${violations.size} files, $total issues.  Trend: $trend"
            } else {
                headerLabel.text = "Security Grade: $grade — scanned ${violations.size} files, $total potential issues."
            }
        }
    }
}
