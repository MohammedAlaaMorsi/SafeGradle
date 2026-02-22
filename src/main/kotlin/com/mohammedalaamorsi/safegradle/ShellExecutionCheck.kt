package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class ShellExecutionCheck : SecurityCheck {
    override val id = "shell_execution"
    override val name = "Shell Command Execution"
    override val description = "Detects attempts to execute arbitrary system commands."

    private val patterns = listOf(
        Pattern.compile("Runtime\\.getRuntime\\(\\)\\.exec", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ProcessBuilder", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.execute\\(\\)", Pattern.CASE_INSENSITIVE), // Groovy string execute
        Pattern.compile("[\"'](sh|bash|zsh|cmd|powershell)[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/bin/sh|/bin/bash|cmd\\.exe", Pattern.CASE_INSENSITIVE)
    )

    override fun check(file: VirtualFile, content: String): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Potential shell execution detected: ${matcher.group()}",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }
        }
        return violations
    }
}
