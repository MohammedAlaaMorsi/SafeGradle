package com.mohammedalaamorsi.safegradle

import com.intellij.icons.AllIcons
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.Messages
import com.intellij.ui.JBColor
import com.intellij.ui.components.*
import com.intellij.util.ui.FormBuilder
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
            font = JBUI.Fonts.small()
            foreground = JBColor.GRAY
        }

        myOsvCheckbox = JBCheckBox("Enable live vulnerability lookup via OSV.dev (requires internet access)", settings.enableOsvLookup).apply {
            font = JBUI.Fonts.label()
        }
        val osvHint = JBLabel("Queries OSV.dev in batches to identify newly published CVEs for declared dependencies.").apply {
            font = JBUI.Fonts.small()
            foreground = JBColor.GRAY
            border = JBUI.Borders.emptyLeft(24)
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
        return domainsChanged || osvChanged
    }

    override fun apply() {
        val settings = SafeGradleSettings.getInstance(project).state
        settings.whitelistedDomains = myDomainsArea?.text
            ?.split("\n")
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.toMutableList() ?: mutableListOf()
        settings.enableOsvLookup = myOsvCheckbox?.isSelected ?: true
    }

    override fun reset() {
        val settings = SafeGradleSettings.getInstance(project).state
        myDomainsArea?.text = settings.whitelistedDomains.joinToString("\n")
        myOsvCheckbox?.isSelected = settings.enableOsvLookup
        val baselineExists = SafeGradleBaseline.exists(project)
        baselineStatusLabel?.text = if (baselineExists) "Baseline file (.safegradle-baseline.json) is active." else "No baseline file saved."
        baselineStatusLabel?.icon = if (baselineExists) AllIcons.General.InspectionsOK else AllIcons.General.Information
        clearBaselineButton?.isEnabled = baselineExists
    }

    override fun disposeUIResources() {
        myDomainsArea = null
        myOsvCheckbox = null
        baselineStatusLabel = null
        clearBaselineButton = null
    }
}

