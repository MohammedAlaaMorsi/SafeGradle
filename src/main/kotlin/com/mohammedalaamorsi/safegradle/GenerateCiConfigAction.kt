package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.ui.Messages
import java.io.File

class GenerateCiConfigAction : AnAction(
    "Generate SafeGradle CI Workflow",
    "Creates .github/workflows/safegradle.yml to run SafeGradle checks in CI and upload results to GitHub Code Scanning",
    null
) {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: return

        val workflowDir = File(basePath, ".github/workflows")
        workflowDir.mkdirs()
        val workflowFile = File(workflowDir, "safegradle.yml")

        if (workflowFile.exists()) {
            val overwrite = Messages.showYesNoDialog(
                project,
                ".github/workflows/safegradle.yml already exists. Overwrite?",
                "Generate CI Workflow",
                null
            )
            if (overwrite != Messages.YES) return
        }

        workflowFile.writeText(WORKFLOW_TEMPLATE)
        Messages.showInfoMessage(
            project,
            "Created .github/workflows/safegradle.yml\n\n" +
            "This workflow will:\n" +
            "• Run ./gradlew safeGradleScan on every push and pull request\n" +
            "• Export findings as SARIF and upload to GitHub Code Scanning\n\n" +
            "Note: The safeGradleScan Gradle task requires the SafeGradle Gradle companion plugin.",
            "CI Workflow Created"
        )
    }

    companion object {
        private val WORKFLOW_TEMPLATE = """
name: SafeGradle Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]

jobs:
  safegradle:
    name: Gradle Build Script Security Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          java-version: '17'
          distribution: 'temurin'

      - name: Grant execute permission for gradlew
        run: chmod +x gradlew

      - name: Run SafeGradle scan
        run: ./gradlew safeGradleScan --no-daemon

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: build/reports/safegradle/safegradle_report.sarif
          category: safegradle
""".trimIndent()
    }
}
