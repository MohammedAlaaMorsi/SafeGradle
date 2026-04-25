package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.vfs.VirtualFile
import java.io.File

object ReportExporter {
    
    fun exportToCsv(violations: Map<VirtualFile, List<SecurityViolation>>, targetFile: File) {
        val sb = StringBuilder()
        sb.append("File,Line,Risk,Message\n")
        
        violations.forEach { (file, list) ->
            list.forEach { v ->
                sb.append("\"${file.path}\",${v.line},${v.riskLevel},\"${v.message.replace("\"", "'")}\"\n")
            }
        }
        
        targetFile.writeText(sb.toString())
    }

    fun exportToJson(violations: Map<VirtualFile, List<SecurityViolation>>, targetFile: File) {
        val sb = StringBuilder()
        sb.append("[\n")
        
        val all = mutableListOf<SecurityViolation>()
        violations.values.forEach { all.addAll(it) }
        
        all.forEachIndexed { i, v ->
            sb.append("  {\n")
            sb.append("    \"file\": \"${v.file.path}\",\n")
            sb.append("    \"line\": ${v.line},\n")
            sb.append("    \"risk\": \"${v.riskLevel}\",\n")
            sb.append("    \"message\": \"${v.message.replace("\"", "'")}\"\n")
            sb.append("  }${if (i < all.size - 1) "," else ""}\n")
        }
        
        sb.append("]")
        targetFile.writeText(sb.toString())
    }
}
