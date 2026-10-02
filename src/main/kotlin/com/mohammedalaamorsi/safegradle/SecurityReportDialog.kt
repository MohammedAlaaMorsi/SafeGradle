package com.mohammedalaamorsi.safegradle

import com.intellij.icons.AllIcons
import com.intellij.openapi.fileEditor.FileEditorManager
import com.intellij.openapi.fileEditor.OpenFileDescriptor
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.table.JBTable
import com.intellij.util.ui.JBUI
import java.awt.*
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.*
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.DefaultTableModel

class SecurityReportDialog(
    private val project: Project?,
    private val violations: Map<VirtualFile, List<SecurityViolation>>
) : DialogWrapper(project) {

    init {
        title = "SafeGradle Security Scan Results"
        setOKButtonText("Close")
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout(0, JBUI.scale(8)))
        panel.preferredSize = Dimension(JBUI.scale(850), JBUI.scale(450))

        val allViolations = violations.values.flatten()
        val high = allViolations.count { it.riskLevel == RiskLevel.HIGH }
        val medium = allViolations.count { it.riskLevel == RiskLevel.MEDIUM }
        val low = allViolations.count { it.riskLevel == RiskLevel.LOW }
        val total = high + medium + low
        val grade = SecurityScore.grade(high, medium, low)

        // Header Panel
        val headerPanel = JPanel(BorderLayout())
        headerPanel.border = JBUI.Borders.empty(4, 0, 8, 0)

        val titleLabel = JBLabel("Found $total security issue${if (total == 1) "" else "s"} in ${violations.size} file${if (violations.size == 1) "" else "s"} (Grade: $grade)").apply {
            font = JBUI.Fonts.label().asBold()
        }
        headerPanel.add(titleLabel, BorderLayout.WEST)

        val chipsPanel = JPanel(FlowLayout(FlowLayout.RIGHT, JBUI.scale(6), 0))
        if (high > 0) {
            chipsPanel.add(JLabel("🔴 $high HIGH").apply {
                font = JBUI.Fonts.smallFont().asBold()
                foreground = JBColor(0xD32F2F, 0xEF5350)
            })
        }
        if (medium > 0) {
            chipsPanel.add(JLabel("🟠 $medium MED").apply {
                font = JBUI.Fonts.smallFont().asBold()
                foreground = JBColor(0xE65100, 0xFFA726)
            })
        }
        if (low > 0) {
            chipsPanel.add(JLabel("🔵 $low LOW").apply {
                font = JBUI.Fonts.smallFont().asBold()
                foreground = JBColor(0x757575, 0x9E9E9E)
            })
        }
        headerPanel.add(chipsPanel, BorderLayout.EAST)
        panel.add(headerPanel, BorderLayout.NORTH)

        val columnNames = arrayOf("File", "Line", "Risk", "Check", "Message")
        val model = object : DefaultTableModel(columnNames, 0) {
            override fun isCellEditable(row: Int, column: Int): Boolean = false
            override fun getColumnClass(col: Int): Class<*> = when (col) {
                1 -> java.lang.Integer::class.java
                2 -> RiskLevel::class.java
                else -> String::class.java
            }
        }

        val flatViolations = mutableListOf<SecurityViolation>()
        violations.forEach { (file, list) ->
            list.forEach { violation ->
                flatViolations.add(violation)
                model.addRow(arrayOf(
                    file.name,
                    violation.line,
                    violation.riskLevel,
                    violation.checkId,
                    violation.message
                ))
            }
        }

        val table = JBTable(model)
        table.rowHeight = JBUI.scale(24)
        table.setShowGrid(false)
        table.intercellSpacing = Dimension(0, 0)
        table.tableHeader.reorderingAllowed = false

        table.columnModel.getColumn(0).preferredWidth = JBUI.scale(160)
        table.columnModel.getColumn(1).apply {
            preferredWidth = JBUI.scale(50)
            maxWidth = JBUI.scale(65)
        }
        table.columnModel.getColumn(2).apply {
            preferredWidth = JBUI.scale(95)
            maxWidth = JBUI.scale(115)
            cellRenderer = object : DefaultTableCellRenderer() {
                init {
                    border = JBUI.Borders.empty(0, 6)
                }
                override fun getTableCellRendererComponent(
                    t: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, col: Int
                ): Component {
                    val c = super.getTableCellRendererComponent(t, value, isSelected, hasFocus, row, col) as JLabel
                    if (value is RiskLevel) {
                        text = "  ${value.name}"
                        icon = when (value) {
                            RiskLevel.HIGH -> AllIcons.General.Error
                            RiskLevel.MEDIUM -> AllIcons.General.Warning
                            RiskLevel.LOW -> AllIcons.General.Information
                        }
                        foreground = if (isSelected) t.selectionForeground else when (value) {
                            RiskLevel.HIGH -> JBColor(0xD32F2F, 0xEF5350)
                            RiskLevel.MEDIUM -> JBColor(0xE65100, 0xFFA726)
                            RiskLevel.LOW -> JBColor(0x757575, 0x9E9E9E)
                        }
                        font = t.font.deriveFont(Font.BOLD, (t.font.size2D - 1f).coerceAtLeast(11f))
                    } else {
                        icon = null
                    }
                    return c
                }
            }
        }
        table.columnModel.getColumn(3).preferredWidth = JBUI.scale(130)
        table.columnModel.getColumn(4).preferredWidth = JBUI.scale(400)

        // Navigation on double click
        table.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                if (e.clickCount == 2 && project != null) {
                    val row = table.selectedRow
                    if (row >= 0 && row < flatViolations.size) {
                        val violation = flatViolations[row]
                        val descriptor = OpenFileDescriptor(project, violation.file, (violation.line - 1).coerceAtLeast(0), 0)
                        FileEditorManager.getInstance(project).openTextEditor(descriptor, true)
                        close(OK_EXIT_CODE)
                    }
                }
            }
        })

        val scrollPane = JBScrollPane(table).apply {
            border = JBUI.Borders.customLine(JBColor.border())
        }
        panel.add(scrollPane, BorderLayout.CENTER)

        val hintLabel = JBLabel("Double-click any row to jump to source code.").apply {
            font = JBUI.Fonts.smallFont()
            foreground = JBColor.GRAY
        }
        panel.add(hintLabel, BorderLayout.SOUTH)

        return panel
    }

    override fun createActions(): Array<Action> {
        val copyAction = object : DialogWrapperAction("Copy Markdown Summary") {
            override fun doAction(e: ActionEvent?) {
                val total = violations.values.sumOf { it.size }
                val md = buildString {
                    appendLine("### 🛡️ SafeGradle Scan Findings ($total issues)")
                    appendLine("| File | Line | Risk | Check | Message |")
                    appendLine("|---|---|---|---|---|")
                    violations.forEach { (file, list) ->
                        list.forEach { v ->
                            appendLine("| `${file.name}` | ${v.line} | **${v.riskLevel}** | `${v.checkId}` | ${v.message.replace("|", "\\|")} |")
                        }
                    }
                }
                Toolkit.getDefaultToolkit().systemClipboard.setContents(StringSelection(md), null)
                JOptionPane.showMessageDialog(window, "Summary copied to clipboard.", "SafeGradle", JOptionPane.INFORMATION_MESSAGE)
            }
        }

        return arrayOf(copyAction, okAction)
    }
}

