package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class DependencyLockCheck : SecurityCheck {
    override val id = "dependency_lock"
    override val name = "Dependency Lock File"
    override val description = "Warns when no dependency locking is configured, allowing builds to silently resolve different transitive dependency versions across environments."

    private val dependencyLockingPattern = Pattern.compile(
        """dependencyLocking\s*\{|lockAllConfigurations\(\)|lockMode\s*=|LockMode\.""",
        Pattern.CASE_INSENSITIVE
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        // Only run on the root build file — avoid duplicate warnings from every module
        if (file.name != "build.gradle" && file.name != "build.gradle.kts") return emptyList()
        if (!isRootBuildFile(file, project)) return emptyList()

        // If any build file in the project already has dependencyLocking configured, don't warn
        if (dependencyLockingPattern.matcher(content).find()) return emptyList()

        // Check if a gradle/dependency-locks/ directory exists
        val projectBase = file.parent ?: return emptyList()
        val gradleDir = projectBase.findChild("gradle")
        if (gradleDir != null && gradleDir.findChild("dependency-locks") != null) return emptyList()

        return listOf(
            SecurityViolation(
                file = file,
                line = 1,
                content = file.name,
                message = "No dependency locking found. Without locking, each build can resolve to a different set of transitive dependencies, " +
                        "enabling silent dependency substitution attacks. Add 'dependencyLocking { lockAllConfigurations() }' or run './gradlew dependencies --write-locks'.",
                riskLevel = RiskLevel.LOW,
                checkId = id
            )
        )
    }

    private fun isRootBuildFile(file: VirtualFile, project: Project?): Boolean {
        val projectBase = project?.basePath ?: return false
        return file.parent?.path == projectBase || file.parent?.parent?.path == projectBase
    }
}
