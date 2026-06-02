package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.io.File

data class BaselineEntry(val filePath: String, val line: Int, val checkId: String, val messagePrefix: String)

object SafeGradleBaseline {

    private fun baselineFile(project: Project): File =
        File(project.basePath, ".safegradle-baseline.json")

    fun save(violations: Map<VirtualFile, List<SecurityViolation>>, project: Project) {
        val entries = violations.entries.flatMap { (file, list) ->
            list.map { v ->
                """{"file":"${file.path.escape()}","line":${v.line},"checkId":"${v.checkId.escape()}","msg":"${v.message.take(60).escape()}"}"""
            }
        }
        baselineFile(project).writeText("[\n${entries.joinToString(",\n")}\n]")
    }

    fun load(project: Project): Set<BaselineEntry> {
        val file = baselineFile(project)
        if (!file.exists()) return emptySet()
        return try {
            val json = file.readText()
            val fileRegex = Regex(""""file"\s*:\s*"([^"]*)"[\s\S]*?"line"\s*:\s*(\d+)[\s\S]*?"checkId"\s*:\s*"([^"]*)"[\s\S]*?"msg"\s*:\s*"([^"]*)"""")
            fileRegex.findAll(json).map { m ->
                BaselineEntry(m.groupValues[1], m.groupValues[2].toInt(), m.groupValues[3], m.groupValues[4])
            }.toSet()
        } catch (e: Exception) {
            emptySet()
        }
    }

    fun isNew(violation: SecurityViolation, baseline: Set<BaselineEntry>): Boolean {
        return baseline.none { b ->
            b.filePath == violation.file.path &&
            b.line == violation.line &&
            b.checkId == violation.checkId &&
            violation.message.startsWith(b.messagePrefix)
        }
    }

    fun exists(project: Project): Boolean = baselineFile(project).exists()

    private fun String.escape() = replace("\\", "\\\\").replace("\"", "\\\"")
}
