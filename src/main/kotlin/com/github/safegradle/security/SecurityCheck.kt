package com.github.safegradle.security

import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.PsiElement

enum class RiskLevel {
    HIGH,    // Remote execution, shell commands, sensitive file exfiltration
    MEDIUM,  // Network access, environment variables, obfuscation
    LOW      // Unusual properties, hardcoded secrets
}

data class SecurityViolation(
    val file: VirtualFile,
    val line: Int,
    val content: String,
    val message: String,
    val riskLevel: RiskLevel
)

interface SecurityCheck {
    val id: String
    val name: String
    val description: String
    
    /**
     * Scans the given file content for security violations.
     * @param file The file being scanned
     * @param content The string content of the file
     * @return List of detected violations
     */
    fun check(file: VirtualFile, content: String): List<SecurityViolation>
}
