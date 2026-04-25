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

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        val lines = content.lines()

        lines.forEachIndexed { index, line ->
            // Skip comments
            if (line.trim().startsWith("//")) {
                return@forEachIndexed
            }

            for (pattern in patterns) {
                val matcher = pattern.matcher(line)
                if (matcher.find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = line.trim(),
                            message = "Potential file exfiltration or data writing detected: ${matcher.group()}",
                            riskLevel = RiskLevel.MEDIUM
                        )
                    )
                }
            }
        }
        return violations
    }
}
