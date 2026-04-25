package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.Project
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBTextArea
import com.intellij.util.ui.FormBuilder
import javax.swing.JComponent
import javax.swing.JPanel

class SafeGradleConfigurable(private val project: Project) : Configurable {

    private var mySettingsComponent: JBTextArea? = null

    override fun getDisplayName(): String = "SafeGradle"

    override fun createComponent(): JComponent {
        mySettingsComponent = JBTextArea(10, 40)
        val settings = SafeGradleSettings.getInstance(project).state
        mySettingsComponent?.text = settings.whitelistedDomains.joinToString("\n")

        return FormBuilder.createFormBuilder()
            .addLabeledComponent(JBLabel("Whitelisted Domains (one per line):"), mySettingsComponent!!, 1, true)
            .addComponentFillVertically(JPanel(), 0)
            .panel
    }

    override fun isModified(): Boolean {
        val settings = SafeGradleSettings.getInstance(project).state
        val currentText = mySettingsComponent?.text ?: ""
        return currentText != settings.whitelistedDomains.joinToString("\n")
    }

    override fun apply() {
        val settings = SafeGradleSettings.getInstance(project).state
        settings.whitelistedDomains = mySettingsComponent?.text
            ?.split("\n")
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.toMutableList() ?: mutableListOf()
    }

    override fun reset() {
        val settings = SafeGradleSettings.getInstance(project).state
        mySettingsComponent?.text = settings.whitelistedDomains.joinToString("\n")
    }

    override fun disposeUIResources() {
        mySettingsComponent = null
    }
}
