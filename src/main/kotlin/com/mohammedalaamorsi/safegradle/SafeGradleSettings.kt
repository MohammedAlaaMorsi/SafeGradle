package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.components.*
import com.intellij.openapi.project.Project

@Service(Service.Level.PROJECT)
@State(name = "SafeGradleSettings", storages = [Storage("safegradle.xml")])
class SafeGradleSettings : PersistentStateComponent<SafeGradleSettings.State> {

    data class State(
        var whitelistedDomains: MutableList<String> = mutableListOf(),
        var ignoredViolations: MutableList<IgnoredViolation> = mutableListOf(),
        var enabledChecks: MutableMap<String, Boolean> = mutableMapOf()
    )

    data class IgnoredViolation(
        var filePath: String = "",
        var line: Int = -1,
        var checkId: String = ""
    )

    private var myState = State()

    override fun getState(): State = myState

    override fun loadState(state: State) {
        myState = state
    }

    companion object {
        fun getInstance(project: Project): SafeGradleSettings = project.service()
    }
}
