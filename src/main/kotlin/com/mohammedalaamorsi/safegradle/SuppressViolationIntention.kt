package com.mohammedalaamorsi.safegradle

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.codeInsight.intention.PsiElementBaseIntentionAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.psi.PsiDocumentManager

class SuppressViolationIntention : PsiElementBaseIntentionAction(), IntentionAction {
    override fun getText(): String = "SafeGradle: Ignore this violation"
    override fun getFamilyName(): String = "SafeGradle"

    override fun isAvailable(project: Project, editor: Editor?, element: PsiElement): Boolean {
        // Only available in Gradle related files
        val fileName = element.containingFile.name
        return fileName.endsWith(".gradle") || fileName.endsWith(".gradle.kts") || fileName == "gradle.properties"
    }

    override fun invoke(project: Project, editor: Editor, element: PsiElement) {
        val document = editor.document
        val lineNumber = document.getLineNumber(element.textOffset)
        val lineEndOffset = document.getLineEndOffset(lineNumber)
        val lineContent = document.getText(com.intellij.openapi.util.TextRange(document.getLineStartOffset(lineNumber), lineEndOffset))

        if (!lineContent.contains("safegradle:ignore")) {
            WriteCommandAction.runWriteCommandAction(project) {
                document.insertString(lineEndOffset, " // safegradle:ignore")
                PsiDocumentManager.getInstance(project).commitDocument(document)
            }
        }
    }

    override fun startInWriteAction(): Boolean = false
}
