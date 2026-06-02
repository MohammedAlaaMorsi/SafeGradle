package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.components.*
import com.intellij.openapi.project.Project

@Service(Service.Level.PROJECT)
@State(name = "SafeGradleScanHistory", storages = [Storage("safegradle_history.xml")])
class SafeGradleScanHistory : PersistentStateComponent<SafeGradleScanHistory.State> {

    data class SnapshotEntry(
        var timestamp: Long = 0L,
        var high: Int = 0,
        var medium: Int = 0,
        var low: Int = 0
    )

    data class State(
        var snapshots: MutableList<SnapshotEntry> = mutableListOf()
    )

    private var myState = State()
    override fun getState(): State = myState
    override fun loadState(state: State) { myState = state }

    fun record(high: Int, medium: Int, low: Int) {
        myState.snapshots.add(SnapshotEntry(System.currentTimeMillis(), high, medium, low))
        if (myState.snapshots.size > 10) {
            myState.snapshots = myState.snapshots.takeLast(10).toMutableList()
        }
    }

    fun snapshots(): List<SnapshotEntry> = myState.snapshots.toList()

    companion object {
        fun getInstance(project: Project): SafeGradleScanHistory = project.service()
    }
}
