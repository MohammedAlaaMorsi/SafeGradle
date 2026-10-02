package com.mohammedalaamorsi.safegradle

import com.intellij.icons.AllIcons
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.ui.JBColor
import com.intellij.ui.components.*
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBFont
import com.intellij.util.ui.JBUI
import java.awt.FlowLayout
import java.awt.Font
import java.io.File
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel

class SafeGradleConfigurable(private val project: Project) : Configurable {

    private var myDomainsArea: JBTextArea? = null
    private var myOsvCheckbox: JBCheckBox? = null
    private var baselineStatusLabel: JBLabel? = null
    private var clearBaselineButton: JButton? = null
    private var myLicenseCheckbox: JBCheckBox? = null
    private var rulesModel: RulesTableModel? = null

    private val severityChoices = arrayOf("Default", "HIGH", "MEDIUM", "LOW")

    /** Rule table rows: [enabled, name, severity override, description]; check ids kept alongside. */
    private class RulesTableModel(val ids: List<String>, rows: List<Array<Any>>) :
        javax.swing.table.DefaultTableModel(rows.toTypedArray(), arrayOf<Any>("On", "Check", "Severity", "Description")) {
        override fun isCellEditable(row: Int, column: Int) = column == 0 || column == 2
        override fun getColumnClass(column: Int): Class<*> = if (column == 0) java.lang.Boolean::class.java else String::class.java

        fun enabledMap(): Map<String, Boolean> = ids.indices.associate { ids[it] to (getValueAt(it, 0) as Boolean) }
        fun severityMap(): Map<String, String> = ids.indices.associate { ids[it] to (getValueAt(it, 2) as String) }
    }

    override fun getDisplayName(): String = "SafeGradle Security"

    override fun createComponent(): JComponent {
        val settings = SafeGradleSettings.getInstance(project).state

        myDomainsArea = JBTextArea(8, 45).apply {
            text = settings.whitelistedDomains.joinToString("\n")
            font = JBFont.create(Font(Font.MONOSPACED, Font.PLAIN, 12))
            border = JBUI.Borders.compound(
                JBUI.Borders.customLine(JBColor.border()),
                JBUI.Borders.empty(4, 6)
            )
        }

        val domainScroll = JBScrollPane(myDomainsArea).apply {
            border = JBUI.Borders.empty()
        }

        val domainHint = JBLabel("<html>Domains listed above will not be flagged by network activity or unverified repository checks.<br>Enter one domain per line (e.g. <code>repo.company.com</code>, <code>nexus.internal.net</code>).</html>").apply {
            font = JBUI.Fonts.smallFont()
            foreground = JBColor.GRAY
        }

        myOsvCheckbox = JBCheckBox("Enable live vulnerability lookup via OSV.dev (requires internet access)", settings.enableOsvLookup).apply {
            font = JBUI.Fonts.label()
        }
        val osvHint = JBLabel("Queries OSV.dev in batches to identify newly published CVEs for declared dependencies.").apply {
            font = JBUI.Fonts.smallFont()
            foreground = JBColor.GRAY
            border = JBUI.Borders.emptyLeft(24)
        }

        myLicenseCheckbox = JBCheckBox("Flag copyleft licences (GPL / AGPL / SSPL) — fetches POMs from Maven Central", settings.enableLicenseLookup)
        val licenseHint = JBLabel("Enable for proprietary projects. Requires internet access; results are cached per session.").apply {
            font = JBUI.Fonts.smallFont()
            foreground = JBColor.GRAY
            border = JBUI.Borders.emptyLeft(24)
        }

        // Rules & checks manager
        val checks = SecurityScanner().checks
        rulesModel = RulesTableModel(checks.map { it.id }, checks.map { c ->
            arrayOf<Any>(
                settings.enabledChecks[c.id] ?: true,
                c.name,
                settings.severityOverrides[c.id]?.takeIf { it in severityChoices } ?: "Default",
                c.description
            )
        })
        val rulesTable = com.intellij.ui.table.JBTable(rulesModel).apply {
            columnModel.getColumn(0).apply { maxWidth = JBUI.scale(40) }
            columnModel.getColumn(1).preferredWidth = JBUI.scale(220)
            columnModel.getColumn(2).apply {
                maxWidth = JBUI.scale(110)
                cellEditor = javax.swing.DefaultCellEditor(com.intellij.openapi.ui.ComboBox(severityChoices))
            }
            columnModel.getColumn(3).preferredWidth = JBUI.scale(420)
            setShowGrid(false)
        }
        val rulesScroll = JBScrollPane(rulesTable).apply { preferredSize = java.awt.Dimension(JBUI.scale(700), JBUI.scale(260)) }
        val rulesHint = JBLabel("Untick to disable a check. Severity overrides the check's built-in level. Team rules in .safegradle.yml take precedence.").apply {
            font = JBUI.Fonts.smallFont()
            foreground = JBColor.GRAY
        }

        // Baseline section
        val baselinePanel = JPanel(FlowLayout(FlowLayout.LEFT, JBUI.scale(8), 0))
        val baselineExists = SafeGradleBaseline.exists(project)
        baselineStatusLabel = JBLabel(
            if (baselineExists) "Baseline file (.safegradle-baseline.json) is active."
            else "No baseline file saved."
        ).apply {
            icon = if (baselineExists) AllIcons.General.InspectionsOK else AllIcons.General.Information
        }
        clearBaselineButton = JButton("Clear Baseline", AllIcons.Actions.Cancel).apply {
            isEnabled = baselineExists
            addActionListener {
                val file = File(project.basePath, ".safegradle-baseline.json")
                if (file.exists() && file.delete()) {
                    Messages.showInfoMessage(project, "Baseline file deleted.", "SafeGradle")
                    isEnabled = false
                    baselineStatusLabel?.text = "No baseline file saved."
                    baselineStatusLabel?.icon = AllIcons.General.Information
                }
            }
        }
        baselinePanel.add(baselineStatusLabel)
        baselinePanel.add(clearBaselineButton)

        return FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Whitelisted Domains:").apply { font = JBUI.Fonts.label().asBold() }, domainScroll, 1, true)
            .addComponent(domainHint)
            .addVerticalGap(12)
            .addSeparator()
            .addVerticalGap(6)
            .addComponent(myOsvCheckbox!!)
            .addComponent(osvHint)
            .addVerticalGap(6)
            .addComponent(myLicenseCheckbox!!)
            .addComponent(licenseHint)
            .addVerticalGap(12)
            .addSeparator()
            .addVerticalGap(6)
            .addLabeledComponent(JBLabel("Rules & Checks:").apply { font = JBUI.Fonts.label().asBold() }, rulesScroll, 1, true)
            .addComponent(rulesHint)
            .addVerticalGap(12)
            .addSeparator()
            .addVerticalGap(6)
            .addLabeledComponent(JBLabel("Scan Baseline:").apply { font = JBUI.Fonts.label().asBold() }, baselinePanel)
            .addComponentFillVertically(JPanel(), 0)
            .panel
    }

    override fun isModified(): Boolean {
        val settings = SafeGradleSettings.getInstance(project).state
        val domainsChanged = (myDomainsArea?.text ?: "") != settings.whitelistedDomains.joinToString("\n")
        val osvChanged = (myOsvCheckbox?.isSelected ?: true) != settings.enableOsvLookup
        val licenseChanged = (myLicenseCheckbox?.isSelected ?: false) != settings.enableLicenseLookup
        return domainsChanged || osvChanged || licenseChanged || rulesChanged(settings)
    }

    private fun rulesChanged(settings: SafeGradleSettings.State): Boolean {
        val model = rulesModel ?: return false
        return model.enabledMap().any { (id, on) -> on != (settings.enabledChecks[id] ?: true) } ||
            model.severityMap().any { (id, sev) -> sev != (settings.severityOverrides[id]?.takeIf { it in severityChoices } ?: "Default") }
    }

    override fun apply() {
        val settings = SafeGradleSettings.getInstance(project).state
        settings.whitelistedDomains = myDomainsArea?.text
            ?.split("\n")
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.toMutableList() ?: mutableListOf()
        settings.enableOsvLookup = myOsvCheckbox?.isSelected ?: true
        settings.enableLicenseLookup = myLicenseCheckbox?.isSelected ?: false
        val rulesDirty = rulesChanged(settings)
        rulesModel?.let { model ->
            // Store only deviations from defaults so new checks stay enabled by default
            for ((id, on) in model.enabledMap()) if (on) settings.enabledChecks.remove(id) else settings.enabledChecks[id] = false
            for ((id, sev) in model.severityMap()) {
                if (sev == "Default") settings.severityOverrides.remove(id) else settings.severityOverrides[id] = sev
            }
        }
        // Cached results were computed under the old rules
        if (rulesDirty) SafeGradleScanCache.getInstance(project).clear()
    }

    override fun reset() {
        val settings = SafeGradleSettings.getInstance(project).state
        myDomainsArea?.text = settings.whitelistedDomains.joinToString("\n")
        myOsvCheckbox?.isSelected = settings.enableOsvLookup
        myLicenseCheckbox?.isSelected = settings.enableLicenseLookup
        rulesModel?.let { model ->
            model.ids.forEachIndexed { row, id ->
                model.setValueAt(settings.enabledChecks[id] ?: true, row, 0)
                model.setValueAt(settings.severityOverrides[id]?.takeIf { it in severityChoices } ?: "Default", row, 2)
            }
        }
        val baselineExists = SafeGradleBaseline.exists(project)
        baselineStatusLabel?.text = if (baselineExists) "Baseline file (.safegradle-baseline.json) is active." else "No baseline file saved."
        baselineStatusLabel?.icon = if (baselineExists) AllIcons.General.InspectionsOK else AllIcons.General.Information
        clearBaselineButton?.isEnabled = baselineExists
    }

    override fun disposeUIResources() {
        myDomainsArea = null
        myOsvCheckbox = null
        myLicenseCheckbox = null
        rulesModel = null
        baselineStatusLabel = null
        clearBaselineButton = null
    }
}

