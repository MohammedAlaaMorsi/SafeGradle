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

    fun exportToSarif(violations: Map<VirtualFile, List<SecurityViolation>>, targetFile: File, pluginVersion: String = "0.0.34") {
        val rules = mutableSetOf<String>()
        violations.values.flatten().forEach { rules.add(it.checkId) }

        val rulesJson = rules.joinToString(",\n") { id ->
            """        {"id":"$id","name":"$id","shortDescription":{"text":"SafeGradle check: $id"}}"""
        }

        val resultsJson = violations.entries.flatMap { (file, list) ->
            list.map { v ->
                val level = when (v.riskLevel) {
                    RiskLevel.HIGH -> "error"
                    RiskLevel.MEDIUM -> "warning"
                    RiskLevel.LOW -> "note"
                }
                val msg = v.message.replace("\"", "\\\"")
                val uri = file.path.replace("\\", "/")
                """    {
      "ruleId":"${v.checkId}",
      "level":"$level",
      "message":{"text":"$msg"},
      "locations":[{"physicalLocation":{"artifactLocation":{"uri":"$uri"},"region":{"startLine":${v.line}}}}]
    }"""
            }
        }.joinToString(",\n")

        val sarif = """{
  "${"$"}schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version":"2.1.0",
  "runs":[{
    "tool":{"driver":{"name":"SafeGradle","version":"$pluginVersion","informationUri":"https://plugins.jetbrains.com/plugin/30319-safegradle","rules":[
$rulesJson
    ]}},
    "results":[
$resultsJson
    ]
  }]
}"""
        targetFile.writeText(sarif)
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
