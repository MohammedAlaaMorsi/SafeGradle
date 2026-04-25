package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.PsiFile

/**
 * Interface for all security checks performed on Gradle files.
 */
interface SecurityCheck {
    val id: String
    val name: String
    val description: String

    /**
     * Regex-based check (fast, works without PSI index)
     */
    fun check(file: VirtualFile, content: String, project: Project? = null, teamConfig: YamlConfig? = null): List<SecurityViolation>

    /**
     * Semantic PSI-based check (accurate, requires project index)
     */
    fun checkPsi(psiFile: PsiFile, project: Project? = null, teamConfig: YamlConfig? = null): List<SecurityViolation> = emptyList()
}
