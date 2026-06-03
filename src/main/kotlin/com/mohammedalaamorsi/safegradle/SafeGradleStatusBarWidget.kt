package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory
import com.intellij.openapi.wm.ToolWindowManager
import com.intellij.util.Consumer
import java.awt.event.MouseEvent

private const val WIDGET_ID = "SafeGradleStatusWidget"

class SafeGradleStatusBarWidgetFactory : StatusBarWidgetFactory {
    override fun getId(): String = WIDGET_ID
    override fun getDisplayName(): String = "SafeGradle"
    override fun isAvailable(project: Project): Boolean = true
    override fun createWidget(project: Project): StatusBarWidget = SafeGradleStatusBarWidget(project)
    override fun disposeWidget(widget: StatusBarWidget) = widget.dispose()
    override fun canBeEnabledOn(statusBar: StatusBar): Boolean = true
}

class SafeGradleStatusBarWidget(private val project: Project) :
    StatusBarWidget, StatusBarWidget.TextPresentation, SafeGradleResultService.ResultsListener {

    private var statusBar: StatusBar? = null
    private var high = 0
    private var medium = 0
    private var low = 0

    init {
        project.messageBus.connect().subscribe(SafeGradleResultService.TOPIC, this)
        // Populate from already-available results if a scan ran before the widget mounted
        val existing = SafeGradleResultService.getInstance(project).getResults()
        if (existing.isNotEmpty()) onResultsUpdated(existing)
    }

    override fun ID(): String = WIDGET_ID
    override fun getPresentation(): StatusBarWidget.WidgetPresentation = this

    override fun install(statusBar: StatusBar) {
        this.statusBar = statusBar
    }

    override fun dispose() {
        statusBar = null
    }

    override fun getText(): String = when {
        high + medium + low == 0 -> "SafeGradle ✓"
        else -> buildString {
            append("SafeGradle")
            if (high > 0) append(" 🔴$high")
            if (medium > 0) append(" 🟠$medium")
            if (low > 0) append(" 🔵$low")
        }
    }

    override fun getTooltipText(): String = when {
        high + medium + low == 0 -> "SafeGradle: No security issues found"
        else -> "SafeGradle: $high HIGH, $medium MEDIUM, $low LOW — click to open"
    }

    override fun getClickConsumer(): Consumer<MouseEvent> = Consumer {
        ToolWindowManager.getInstance(project).getToolWindow("SafeGradle")?.show()
    }

    override fun getAlignment(): Float = 0f

    override fun onResultsUpdated(violations: Map<VirtualFile, List<SecurityViolation>>) {
        high = 0; medium = 0; low = 0
        violations.values.flatten().forEach {
            when (it.riskLevel) {
                RiskLevel.HIGH -> high++
                RiskLevel.MEDIUM -> medium++
                RiskLevel.LOW -> low++
            }
        }
        ApplicationManager.getApplication().invokeLater {
            statusBar?.updateWidget(WIDGET_ID)
        }
    }
}
