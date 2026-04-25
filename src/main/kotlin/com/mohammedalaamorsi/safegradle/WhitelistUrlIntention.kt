package com.mohammedalaamorsi.safegradle

import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.codeInsight.intention.PsiElementBaseIntentionAction
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.project.Project
import com.intellij.psi.PsiElement
import java.util.regex.Pattern

class WhitelistUrlIntention : PsiElementBaseIntentionAction(), IntentionAction {
    override fun getText(): String = "SafeGradle: Whitelist this domain"
    override fun getFamilyName(): String = "SafeGradle"

    private val urlPattern = Pattern.compile("(http|https)://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")

    override fun isAvailable(project: Project, editor: Editor?, element: PsiElement): Boolean {
        val text = element.text
        return urlPattern.matcher(text).find()
    }

    override fun invoke(project: Project, editor: Editor, element: PsiElement) {
        val matcher = urlPattern.matcher(element.text)
        if (matcher.find()) {
            val url = matcher.group()
            val domain = url.removePrefix("https://").removePrefix("http://")
                .substringBefore("/").substringBefore(":")
            
            val settings = SafeGradleSettings.getInstance(project)
            settings.state.whitelistedDomains.add(domain)
            
            // Trigger a re-scan by clearing cache or similar if we had one
            // For now, the annotator will pick it up on next run
        }
    }

    override fun startInWriteAction(): Boolean = false
}
