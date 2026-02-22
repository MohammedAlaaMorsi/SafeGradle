package com.mohammedalaamorsi.safegradle

import com.intellij.ide.DataManager
import com.intellij.ide.impl.isTrusted
import com.intellij.ide.trustedProjects.TrustedProjects
import com.intellij.openapi.actionSystem.ActionManager
import com.intellij.openapi.actionSystem.ActionUiKind
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.actionSystem.ex.ActionUtil
import com.intellij.openapi.fileEditor.FileEditor
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.ui.EditorNotificationPanel
import com.intellij.ui.EditorNotificationProvider
import java.util.function.Function
import javax.swing.JComponent

class SafeGradleNotificationProvider : EditorNotificationProvider {
    
    override fun collectNotificationData(
        project: Project,
        file: VirtualFile
    ): Function<in FileEditor, out JComponent?>? {
        // Only show if the project is NOT trusted (Safe Mode)
        if (TrustedProjects.isProjectTrusted(project)) {
            return null
        }
        
        return Function { fileEditor: FileEditor ->
            val panel = EditorNotificationPanel(fileEditor, EditorNotificationPanel.Status.Warning)
            panel.text = "This project is in Safe Mode. Scan files with SafeGradle to detect potential security risks before trusting."
            
            panel.createActionLabel("Scan with SafeGradle") {
                val action = ActionManager.getInstance().getAction("com.mohammedalaamorsi.safegradle.scan")
                if (action != null) {
                    val context = DataManager.getInstance().getDataContext(panel)
                    val event = AnActionEvent.createEvent(context, action.templatePresentation.clone(), "SafeModeBanner", ActionUiKind.NONE, null)
                    ActionUtil.performAction(action, event)
                }
            }
            
            panel
        }
    }
}
