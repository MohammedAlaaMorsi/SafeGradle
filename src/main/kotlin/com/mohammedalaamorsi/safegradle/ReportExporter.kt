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

    fun exportToHtml(
        violations: Map<VirtualFile, List<SecurityViolation>>,
        targetFile: File,
        pluginVersion: String = ""
    ) {
        val all = violations.values.flatten()
        val high = all.count { it.riskLevel == RiskLevel.HIGH }
        val medium = all.count { it.riskLevel == RiskLevel.MEDIUM }
        val low = all.count { it.riskLevel == RiskLevel.LOW }
        val total = all.size
        val grade = SecurityScore.grade(high, medium, low)
        val date = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm").format(java.util.Date())

        fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        fun pct(n: Int) = if (total == 0) 0 else n * 100 / total

        val fileSections = violations.entries.joinToString("\n") { (file, list) ->
            val rows = list.joinToString("\n") { v ->
                val fix = v.fixVersion?.let { "<br><em>Fix: upgrade to $it</em>" } ?: ""
                """<tr><td>${v.line}</td><td class="risk-${v.riskLevel.name.lowercase()}">${v.riskLevel}</td><td>${esc(v.message)}$fix</td><td><code>${esc(v.content.take(120))}</code></td></tr>"""
            }
            """<h2>${esc(file.path)}</h2>
<table><tr><th>Line</th><th>Risk</th><th>Message</th><th>Code</th></tr>
$rows
</table>"""
        }

        val html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>SafeGradle Security Report</title>
<style>
body{font-family:system-ui,sans-serif;margin:2em auto;max-width:1100px;color:#222}
h1{margin-bottom:0} .meta{color:#666;margin-bottom:1.5em}
.cards{display:flex;gap:1em;margin:1em 0}
.card{flex:1;border:1px solid #ddd;border-radius:8px;padding:1em;text-align:center}
.card .num{font-size:2em;font-weight:bold}
.grade{font-size:2.5em;font-weight:bold}
.grade-A{color:#2e7d32}.grade-B{color:#558b2f}.grade-C{color:#f9a825}.grade-D{color:#ef6c00}.grade-F{color:#c62828}
.bar{display:flex;height:14px;border-radius:7px;overflow:hidden;margin:1em 0;background:#eee}
.bar .h{background:#c62828}.bar .m{background:#ef6c00}.bar .l{background:#1565c0}
table{border-collapse:collapse;width:100%;margin-bottom:2em}
th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;vertical-align:top}
th{background:#f5f5f5}
.risk-high{color:#c62828;font-weight:bold}.risk-medium{color:#ef6c00;font-weight:bold}.risk-low{color:#1565c0}
code{font-size:0.85em;word-break:break-all}
</style></head><body>
<h1>SafeGradle Security Report</h1>
<div class="meta">Generated $date${if (pluginVersion.isNotEmpty()) " — SafeGradle $pluginVersion" else ""}</div>
<div class="cards">
<div class="card"><div class="grade grade-$grade">$grade</div>Security Grade</div>
<div class="card"><div class="num risk-high">$high</div>HIGH</div>
<div class="card"><div class="num risk-medium">$medium</div>MEDIUM</div>
<div class="card"><div class="num risk-low">$low</div>LOW</div>
</div>
<div class="bar"><div class="h" style="width:${pct(high)}%"></div><div class="m" style="width:${pct(medium)}%"></div><div class="l" style="width:${pct(low)}%"></div></div>
${if (total == 0) "<p>No security issues found. 🎉</p>" else fileSections}
</body></html>"""
        targetFile.writeText(html)
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
