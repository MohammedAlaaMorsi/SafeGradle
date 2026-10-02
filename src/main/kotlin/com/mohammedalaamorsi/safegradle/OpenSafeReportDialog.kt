package com.mohammedalaamorsi.safegradle

import com.intellij.icons.AllIcons
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.JBColor
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.table.JBTable
import com.intellij.util.ui.JBUI
import java.awt.*
import java.awt.event.ActionEvent
import javax.swing.*
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.DefaultTableModel

class OpenSafeReportDialog(
    private val violations: Map<VirtualFile, List<SecurityViolation>>,
    private val projectPath: String
) : DialogWrapper(null, true) {

    init {
        title = "SafeGradle: Security Risks Detected"
        init()
    }

    override fun createCenterPanel(): JComponent {
        val panel = JPanel(BorderLayout(0, JBUI.scale(10)))
        panel.preferredSize = Dimension(JBUI.scale(750), JBUI.scale(420))

        val all = violations.values.flatten()
        val high = all.count { it.riskLevel == RiskLevel.HIGH }
        val medium = all.count { it.riskLevel == RiskLevel.MEDIUM }
        val low = all.count { it.riskLevel == RiskLevel.LOW }

        // Top warning banner
        val banner = JPanel(BorderLayout(JBUI.scale(12), 0)).apply {
            border = BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(JBColor(0xE57373, 0x5C1D1D), 1, true),
                JBUI.Borders.empty(10, 12)
            )
            background = JBColor(0xFFEBEE, 0x2A1515)
        }

        val iconLabel = JLabel(AllIcons.General.WarningDialog)
        banner.add(iconLabel, BorderLayout.WEST)

        val warningText = JLabel(
            "<html><b>Potential security threats were detected in the build scripts of this project.</b><br>" +
            "Gradle build scripts can execute arbitrary code during sync or build. Review findings below before opening.</html>"
        ).apply {
            font = JBUI.Fonts.label()
        }
        banner.add(warningText, BorderLayout.CENTER)

        val countsPanel = JPanel(FlowLayout(FlowLayout.RIGHT, JBUI.scale(6), 0)).apply {
            isOpaque = false
        }
        if (high > 0) {
            countsPanel.add(JLabel("🔴 $high HIGH").apply {
                font = JBUI.Fonts.smallFont().asBold()
                foreground = JBColor(0xD32F2F, 0xEF5350)
            })
        }
        if (medium > 0) {
            countsPanel.add(JLabel("🟠 $medium MED").apply {
                font = JBUI.Fonts.smallFont().asBold()
                foreground = JBColor(0xE65100, 0xFFA726)
            })
        }
        if (low > 0) {
            countsPanel.add(JLabel("🔵 $low LOW").apply {
                font = JBUI.Fonts.smallFont().asBold()
                foreground = JBColor(0x757575, 0x9E9E9E)
            })
        }
        banner.add(countsPanel, BorderLayout.EAST)
        panel.add(banner, BorderLayout.NORTH)

        // Center: Findings Table
        val colNames = arrayOf("File", "Line", "Risk", "Description")
        val model = object : DefaultTableModel(colNames, 0) {
            override fun isCellEditable(row: Int, col: Int): Boolean = false
            override fun getColumnClass(col: Int): Class<*> = when (col) {
                1 -> java.lang.Integer::class.java
                2 -> RiskLevel::class.java
                else -> String::class.java
            }
        }

        violations.forEach { (file, list) ->
            list.forEach { v ->
                model.addRow(arrayOf(file.name, v.line, v.riskLevel, v.message))
            }
        }

        val table = JBTable(model)
        table.rowHeight = JBUI.scale(24)
        table.setShowGrid(false)
        table.intercellSpacing = Dimension(0, 0)

        table.columnModel.getColumn(0).preferredWidth = JBUI.scale(150)
        table.columnModel.getColumn(1).apply {
            preferredWidth = JBUI.scale(50)
            maxWidth = JBUI.scale(60)
        }
        table.columnModel.getColumn(2).apply {
            preferredWidth = JBUI.scale(90)
            maxWidth = JBUI.scale(105)
            cellRenderer = object : DefaultTableCellRenderer() {
                init { border = JBUI.Borders.empty(0, 6) }
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
        table.columnModel.getColumn(3).preferredWidth = JBUI.scale(420)

        panel.add(JBScrollPane(table).apply {
            border = JBUI.Borders.customLine(JBColor.border())
        }, BorderLayout.CENTER)

        return panel
    }

    override fun createActions(): Array<Action> {
        val cancelAction = DialogWrapperExitAction("Cancel", CANCEL_EXIT_CODE)
        cancelAction.putValue(Action.DEFAULT, true)

        val proceedAction = object : DialogWrapperAction("Trust and Open Anyway") {
            override fun doAction(e: ActionEvent?) {
                close(OK_EXIT_CODE)
            }
        }

        return arrayOf(cancelAction, proceedAction)
    }
}

