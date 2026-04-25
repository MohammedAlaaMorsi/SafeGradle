package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.guessProjectDir

import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile
import com.intellij.openapi.vfs.VirtualFile

class SafeGradleAnnotator : ExternalAnnotator<PsiFile, List<SecurityViolation>>() {

    override fun collectInformation(file: PsiFile, editor: Editor, hasErrors: Boolean): PsiFile? {
        val fileName = file.name
        if (fileName.endsWith(".gradle") || fileName.endsWith(".gradle.kts") || fileName == "gradle.properties") {
            return file
        }
        return null
    }

    override fun doAnnotate(collectedInfo: PsiFile?): List<SecurityViolation> {
        if (collectedInfo == null) return emptyList()
        
        val virtualFile = collectedInfo.virtualFile ?: return emptyList()
        val project = collectedInfo.project
        
        // Load team-wide config if exists
        val baseDir = project.guessProjectDir()
        val configFile = baseDir?.findChild(".safegradle.yml")
        val teamConfig = configFile?.let { 
            try {
                YamlConfigParser.parse(it.inputStream)
            } catch (e: Exception) {
                null
            }
        }

        val scanner = SecurityScanner()
        val results = scanner.scanDirectory(virtualFile.parent, project, teamConfig)
        
        return results[virtualFile] ?: emptyList()
    }

    override fun apply(file: PsiFile, annotationResult: List<SecurityViolation>, holder: AnnotationHolder) {
        for (violation in annotationResult) {
            val document = file.viewProvider.document ?: continue
            if (violation.line <= 0 || violation.line > document.lineCount) continue
            
            val startOffset = document.getLineStartOffset(violation.line - 1)
            val endOffset = document.getLineEndOffset(violation.line - 1)
            val range = TextRange(startOffset, endOffset)
            
            val severity = when (violation.riskLevel) {
                RiskLevel.HIGH -> HighlightSeverity.ERROR
                RiskLevel.MEDIUM -> HighlightSeverity.WARNING
                RiskLevel.LOW -> HighlightSeverity.WEAK_WARNING
            }
            
            holder.newAnnotation(severity, "SafeGradle: ${violation.message}")
                .range(range)
                .create()
        }
    }
}
