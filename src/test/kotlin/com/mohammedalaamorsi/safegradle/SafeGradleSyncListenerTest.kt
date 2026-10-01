package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.externalSystem.model.ProjectSystemId
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskId
import com.intellij.openapi.externalSystem.model.task.ExternalSystemTaskType
import com.intellij.testFramework.fixtures.BasePlatformTestCase

class SafeGradleSyncListenerTest : BasePlatformTestCase() {

    fun `test listener ignores non-gradle tasks`() {
        val listener = SafeGradleSyncListener()
        val mavenId = ExternalSystemTaskId.create(ProjectSystemId("MAVEN"), ExternalSystemTaskType.RESOLVE_PROJECT, project)
        // Should return early and not throw
        listener.onStart(mavenId, project.basePath)
        listener.onSuccess(mavenId)
    }

    fun `test listener ignores non-resolve tasks`() {
        val listener = SafeGradleSyncListener()
        val taskId = ExternalSystemTaskId.create(ProjectSystemId("GRADLE"), ExternalSystemTaskType.EXECUTE_TASK, project)
        // Should return early without issues
        listener.onStart(taskId, project.basePath)
        listener.onSuccess(taskId)
    }

    fun `test listener runs cleanly on clean project`() {
        val listener = SafeGradleSyncListener()
        val syncId = ExternalSystemTaskId.create(ProjectSystemId("GRADLE"), ExternalSystemTaskType.RESOLVE_PROJECT, project)
        myFixture.configureByText("build.gradle", "plugins { id 'java' }")
        listener.onStart(syncId, project.basePath)
    }
}
