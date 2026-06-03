package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextArea
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

class SafeGradleConfigurable(private val project: Project) : Configurable {

    private var myDomainsArea: JBTextArea? = null
    private var myOsvCheckbox: JBCheckBox? = null

    override fun getDisplayName(): String = "SafeGradle"

    override fun createComponent(): JComponent {
        val settings = SafeGradleSettings.getInstance(project).state

        myDomainsArea = JBTextArea(10, 40)
        myDomainsArea?.text = settings.whitelistedDomains.joinToString("\n")

        myOsvCheckbox = JBCheckBox("Enable live vulnerability lookup via OSV.dev (requires internet)", settings.enableOsvLookup)

        return FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Whitelisted Domains (one per line):"), myDomainsArea!!, 1, true)
            .addComponent(myOsvCheckbox!!)
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
    }

    override fun disposeUIResources() {
        myDomainsArea = null
        myOsvCheckbox = null
    }
}
