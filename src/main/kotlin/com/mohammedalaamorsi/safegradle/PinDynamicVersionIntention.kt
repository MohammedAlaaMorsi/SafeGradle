package com.mohammedalaamorsi.safegradle

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.codeInsight.intention.PsiElementBaseIntentionAction
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import java.util.regex.Pattern

class PinDynamicVersionIntention : PsiElementBaseIntentionAction(), IntentionAction {
    override fun getText(): String = "SafeGradle: Replace dynamic version with placeholder (pin manually)"
    override fun getFamilyName(): String = "SafeGradle"

    private val dynamicVersionPattern = Pattern.compile(
        """(['"])([^'"]+):([^'"]+):(\+|latest\.release|latest\.integration|[^'"]*-SNAPSHOT)\1"""
    )

    override fun isAvailable(project: Project, editor: Editor?, element: PsiElement): Boolean {
        val line = currentLine(editor) ?: return false
        return dynamicVersionPattern.matcher(line).find()
    }

    override fun invoke(project: Project, editor: Editor, element: PsiElement) {
        val document = editor.document
        val lineNumber = document.getLineNumber(editor.caretModel.offset)
        val start = document.getLineStartOffset(lineNumber)
        val end = document.getLineEndOffset(lineNumber)
        val lineText = document.getText(com.intellij.openapi.util.TextRange(start, end))

        val matcher = dynamicVersionPattern.matcher(lineText)
        if (!matcher.find()) return

        val group = matcher.group(2)
        val artifact = matcher.group(3)
        // Replace dynamic version with a TODO placeholder so the developer pins it explicitly
        val fixed = lineText.substring(0, matcher.start(4)) + "TODO_PIN_VERSION" + lineText.substring(matcher.end(4))
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
