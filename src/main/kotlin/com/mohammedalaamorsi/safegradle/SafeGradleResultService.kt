package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.util.messages.Topic

@Service(Service.Level.PROJECT)
class SafeGradleResultService(private val project: Project) {
    
    private var lastResults: Map<VirtualFile, List<SecurityViolation>> = emptyMap()

    interface ResultsListener {
        fun onResultsUpdated(violations: Map<VirtualFile, List<SecurityViolation>>)
    }

    companion object {
        val TOPIC = Topic.create("SafeGradle Results Updated", ResultsListener::class.java)
        fun getInstance(project: Project): SafeGradleResultService = project.service()
    }

    fun setResults(violations: Map<VirtualFile, List<SecurityViolation>>) {
        lastResults = violations
        project.messageBus.syncPublisher(TOPIC).onResultsUpdated(violations)
    }

    fun getResults(): Map<VirtualFile, List<SecurityViolation>> = lastResults
}
