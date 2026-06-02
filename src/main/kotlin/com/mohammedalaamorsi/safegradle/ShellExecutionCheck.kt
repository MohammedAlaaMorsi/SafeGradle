package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class ShellExecutionCheck : SecurityCheck {
    override val id = "shell_execution"
    override val name = "Shell Command Execution"
    override val description = "Detects attempts to execute arbitrary system commands."

    private val patterns = listOf(
        Pattern.compile("Runtime\\.getRuntime\\(\\)\\.exec", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ProcessBuilder", Pattern.CASE_INSENSITIVE),
        Pattern.compile("[\"'](sh|bash|zsh|cmd|powershell)[\"']", Pattern.CASE_INSENSITIVE),
        Pattern.compile("/bin/sh|/bin/bash|cmd\\.exe", Pattern.CASE_INSENSITIVE)
    )

    // Groovy string .execute() is common for git versioning; only flag when the string looks like
    // a shell invocation (contains shell keywords, pipes, or redirects) rather than a plain command.
    private val executePattern = Pattern.compile("\\.execute\\(\\)", Pattern.CASE_INSENSITIVE)
    private val shellIndicators = Pattern.compile("[|><&;]|\\$\\(|`|\\bsh\\b|\\bbash\\b|\\bsudo\\b|\\brm\\b|\\bcurl\\b|\\bwget\\b", Pattern.CASE_INSENSITIVE)

    // commandLine(...) with ${} interpolation — attacker-controlled input injected into a shell command
    private val commandLineInterpolation = Pattern.compile(
        """commandLine\s*[\(\[,].*\$\{""",
        Pattern.CASE_INSENSITIVE
    )
    private val destructiveInterpolated = setOf("rm", "del", "format", "curl", "wget", "nc", "chmod", "chown", "dd", "mkfs")

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("//") || stripped.startsWith("#")) return@forEachIndexed

            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = stripped,
                            message = "Potential shell execution detected: ${matcher.group()}",
                            riskLevel = RiskLevel.HIGH
                        )
                    )
                }
            }

            // .execute() in Groovy is legitimate for simple git/version commands.
            // Only flag when the line also contains shell-specific operators or dangerous commands.
            if (executePattern.matcher(line).find() && shellIndicators.matcher(line).find()) {
                violations.add(
                    SecurityViolation(
                        file = file,
                        line = index + 1,
                        content = stripped,
                        message = "Suspicious shell execution via .execute() with shell operators or dangerous commands detected.",
                        riskLevel = RiskLevel.HIGH
                    )
                )
            }

            // commandLine with ${} interpolation — user-controlled input in a process exec call
            if (commandLineInterpolation.matcher(line).find()) {
                val hasDestructive = destructiveInterpolated.any { cmd ->
                    line.contains(cmd, ignoreCase = true)
                }
                violations.add(
                    SecurityViolation(
                        file = file,
                        line = index + 1,
                        content = stripped,
                        message = if (hasDestructive)
                            "String interpolation with a destructive command in commandLine — attacker-controlled project properties can inject arbitrary commands."
                        else
                            "String interpolation inside commandLine — verify that interpolated values cannot be controlled by untrusted input.",
                        riskLevel = if (hasDestructive) RiskLevel.HIGH else RiskLevel.MEDIUM
                    )
                )
            }
        }
        return violations
    }
}
