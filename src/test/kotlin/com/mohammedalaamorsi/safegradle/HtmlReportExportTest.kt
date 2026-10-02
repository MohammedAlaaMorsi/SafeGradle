package com.mohammedalaamorsi.safegradle

import com.intellij.testFramework.fixtures.BasePlatformTestCase
import java.io.File

class HtmlReportExportTest : BasePlatformTestCase() {

    fun `test html report contains grade counts and findings`() {
        val file = myFixture.configureByText("build.gradle", "implementation 'a:b:1.0'").virtualFile
        val violations = mapOf(
            file to listOf(
                SecurityViolation(file, 1, "implementation 'a:b:1.0'", "Vulnerable <dep>", RiskLevel.HIGH, "vuln", fixVersion = "2.0"),
                SecurityViolation(file, 2, "x", "Minor issue", RiskLevel.LOW, "misc")
            )
        )
        val target = File.createTempFile("safegradle_report", ".html")
        try {
            ReportExporter.exportToHtml(violations, target, "0.0.37")
            val html = target.readText()
            assertTrue(html.contains("grade-C")) // 1 HIGH + 1 LOW = weighted 6 → C
            assertTrue(html.contains(">1</div>HIGH"))
            assertTrue(html.contains("Vulnerable &lt;dep&gt;")) // HTML-escaped
            assertTrue(html.contains("upgrade to 2.0"))
            assertTrue(html.contains("0.0.37"))
            assertFalse(html.contains("Vulnerable <dep>")) // raw markup must not leak
        } finally {
            target.delete()
        }
    }

    fun `test html report for clean project shows grade A`() {
        val target = File.createTempFile("safegradle_report", ".html")
        try {
            ReportExporter.exportToHtml(emptyMap(), target)
            val html = target.readText()
            assertTrue(html.contains("grade-A"))
            assertTrue(html.contains("No security issues found"))
        } finally {
            target.delete()
        }
    }
}
