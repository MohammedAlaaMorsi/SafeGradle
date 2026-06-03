package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class FileExfiltrationCheck : SecurityCheck {
    override val id = "file_exfiltration"
    override val name = "File Exfiltration Risk"
    override val description = "Detects file writing and copying operations that could be used to steal data."

    private val patterns = listOf(
        Pattern.compile("FileOutputStream", Pattern.CASE_INSENSITIVE),
        Pattern.compile("FileWriter", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Files\\.write", Pattern.CASE_INSENSITIVE),
        Pattern.compile("Files\\.copy", Pattern.CASE_INSENSITIVE),
        Pattern.compile("\\.transferTo\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("ZipOutputStream", Pattern.CASE_INSENSITIVE)
    )

    // Writing to .git/hooks/ installs a persistent hook that survives the build
    private val gitHookPattern = Pattern.compile("""\Q.git/hooks/\E|\.git[/\\]hooks[/\\]""", Pattern.CASE_INSENSITIVE)

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
                            message = "Potential file exfiltration or data writing detected: ${matcher.group()}",
                            riskLevel = RiskLevel.MEDIUM
                        )
                    )
                }
            }

            // Git hook tampering — writing to .git/hooks/ creates persistent code that runs on every commit
            if (gitHookPattern.matcher(line).find()) {
                violations.add(
                    SecurityViolation(
                        file = file,
                        line = index + 1,
                        content = stripped,
                        message = "Possible git hook tampering: reference to '.git/hooks/' detected. Writing to this directory installs persistent code that executes on every git operation.",
                        riskLevel = RiskLevel.HIGH
                    )
                )
            }
        }
        return violations
    }
}
