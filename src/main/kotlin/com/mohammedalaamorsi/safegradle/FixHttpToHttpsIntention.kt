package com.mohammedalaamorsi.safegradle

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.codeInsight.intention.PsiElementBaseIntentionAction
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiDocumentManager

class FixHttpToHttpsIntention : PsiElementBaseIntentionAction(), IntentionAction {
    override fun getText(): String = "SafeGradle: Replace http:// with https://"
    override fun getFamilyName(): String = "SafeGradle"

    override fun isAvailable(project: Project, editor: Editor?, element: PsiElement): Boolean {
        val line = currentLine(editor) ?: return false
        return line.contains("http://") && !line.trim().startsWith("//") && !line.trim().startsWith("#")
    }

    override fun invoke(project: Project, editor: Editor, element: PsiElement) {
        val document = editor.document
        val lineNumber = document.getLineNumber(editor.caretModel.offset)
        val start = document.getLineStartOffset(lineNumber)
        val end = document.getLineEndOffset(lineNumber)
        val lineText = document.getText(com.intellij.openapi.util.TextRange(start, end))
        val fixed = lineText.replace("http://", "https://")
        WriteCommandAction.runWriteCommandAction(project) {
            document.replaceString(start, end, fixed)
            PsiDocumentManager.getInstance(project).commitDocument(document)
        }
    }

    private fun currentLine(editor: Editor?): String? {
        editor ?: return null
        val doc = editor.document
        val line = doc.getLineNumber(editor.caretModel.offset)
        return doc.getText(com.intellij.openapi.util.TextRange(doc.getLineStartOffset(line), doc.getLineEndOffset(line)))
    }

    override fun startInWriteAction(): Boolean = false
}
