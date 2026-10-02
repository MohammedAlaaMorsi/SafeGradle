package com.mohammedalaamorsi.safegradle

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.codeInsight.intention.PsiElementBaseIntentionAction
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiFile

class FixGradleWrapperChecksumIntention : PsiElementBaseIntentionAction(), IntentionAction {
    override fun getText(): String = "SafeGradle: Add official SHA-256 checksum to gradle-wrapper.properties"
    override fun getFamilyName(): String = "SafeGradle"

    override fun isAvailable(project: Project, editor: Editor?, element: PsiElement): Boolean {
        val file: PsiFile = element.containingFile ?: return false
        if (file.name != "gradle-wrapper.properties") return false
        val doc = editor?.document ?: return false
        val text = doc.text
        val versionMatch = Regex("""gradle-([0-9.]+)-(bin|all)\.zip""").find(text) ?: return false
        val version = versionMatch.groupValues[1]
        val type = versionMatch.groupValues[2]
        val expected = GradleWrapperIntegrityCheck.lookupExpectedChecksum(version, type) ?: return false

        // If checksum already exists and matches expected, no action needed
        val existingMatch = Regex("""distributionSha256Sum\s*=\s*([a-fA-F0-9]+)""").find(text)
        if (existingMatch != null && existingMatch.groupValues[1].equals(expected, ignoreCase = true)) {
            return false
        }
        return true
    }

    override fun invoke(project: Project, editor: Editor, element: PsiElement) {
        val doc = editor.document
        val text = doc.text
        val versionMatch = Regex("""gradle-([0-9.]+)-(bin|all)\.zip""").find(text) ?: return
        val version = versionMatch.groupValues[1]
        val type = versionMatch.groupValues[2]
        val expected = GradleWrapperIntegrityCheck.lookupExpectedChecksum(version, type) ?: return

        WriteCommandAction.runWriteCommandAction(project) {
            val propKey = "distributionSha256Sum="
            if (text.contains(propKey)) {
                val regex = Regex("""distributionSha256Sum\s*=.*""")
                val newText = regex.replace(text, "distributionSha256Sum=$expected")
                doc.setText(newText)
            } else {
                val sep = if (text.endsWith("\n")) "" else "\n"
                doc.insertString(doc.textLength, "${sep}distributionSha256Sum=$expected\n")
            }
            PsiDocumentManager.getInstance(project).commitDocument(doc)
        }
    }

    override fun startInWriteAction(): Boolean = false
}
