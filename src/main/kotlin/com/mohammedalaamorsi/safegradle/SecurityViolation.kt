package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.VirtualFile

enum class RiskLevel {
    LOW, MEDIUM, HIGH
}

data class SecurityViolation(
    val file: VirtualFile,
    val line: Int,
    val content: String,
    val message: String,
    val riskLevel: RiskLevel,
    val checkId: String = "unknown",
    /** Version that remediates the finding, when known — enables one-click upgrade. */
    val fixVersion: String? = null
)
