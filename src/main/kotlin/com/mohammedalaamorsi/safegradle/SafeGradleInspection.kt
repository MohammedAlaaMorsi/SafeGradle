package com.mohammedalaamorsi.safegradle

import com.intellij.codeInspection.LocalInspectionTool
import com.intellij.codeInspection.LocalInspectionToolSession
import com.intellij.codeInspection.ProblemHighlightType
import com.intellij.codeInspection.ProblemsHolder
import com.intellij.openapi.project.guessProjectDir
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiElementVisitor
import com.intellij.psi.PsiFile

class SafeGradleInspection : LocalInspectionTool() {

    override fun getDisplayName(): String = "SafeGradle Security Check"
    override fun getGroupDisplayName(): String = "SafeGradle"
    override fun getShortName(): String = "SafeGradleSecurity"
    override fun isEnabledByDefault(): Boolean = true

    override fun buildVisitor(
        holder: ProblemsHolder,
        isOnTheFly: Boolean,
        session: LocalInspectionToolSession
    ): PsiElementVisitor {
        val file = holder.file
        if (!isGradleFile(file)) return PsiElementVisitor.EMPTY_VISITOR

        return object : PsiElementVisitor() {
            override fun visitFile(psiFile: PsiFile) {
                val virtualFile = psiFile.virtualFile ?: return
                val project = psiFile.project
                val content = try { String(virtualFile.contentsToByteArray()) } catch (e: Exception) { return }

                val baseDir = project.guessProjectDir()
                val teamConfig = try {
                    baseDir?.findChild(".safegradle.yml")
                        ?.let { YamlConfigParser.parse(it.inputStream) }
                } catch (_: Exception) { null }

                val scanner = SecurityScanner()
                val violations = scanner.scanDirectory(virtualFile.parent ?: return, project, teamConfig)
                val fileViolations = violations[virtualFile] ?: return

                val document = psiFile.viewProvider.document ?: return

                for (v in fileViolations) {
                    if (v.line <= 0 || v.line > document.lineCount) continue
                    val startOffset = document.getLineStartOffset(v.line - 1)
                    val endOffset = document.getLineEndOffset(v.line - 1)
                    val range = com.intellij.openapi.util.TextRange(startOffset, endOffset)
                    val element = psiFile.findElementAt(startOffset) ?: continue

                    val highlightType = when (v.riskLevel) {
                        RiskLevel.HIGH -> ProblemHighlightType.GENERIC_ERROR
                        RiskLevel.MEDIUM -> ProblemHighlightType.WARNING
                        RiskLevel.LOW -> ProblemHighlightType.WEAK_WARNING
                    }

                    holder.registerProblem(element, "SafeGradle [${v.riskLevel}]: ${v.message}", highlightType)
                }
            }
        }
    }

    private fun isGradleFile(file: PsiFile): Boolean {
        val name = file.name
        return name.endsWith(".gradle") || name.endsWith(".gradle.kts") ||
               name == "gradle.properties" || name == "libs.versions.toml"
    }
}
