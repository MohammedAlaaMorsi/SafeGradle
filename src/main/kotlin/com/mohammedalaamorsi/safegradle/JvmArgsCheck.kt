package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.util.regex.Pattern

class JvmArgsCheck : SecurityCheck {
    override val id = "dangerous_jvm_args"
    override val name = "Dangerous JVM Arguments"
    override val description = "Detects dangerous JVM flags in org.gradle.jvmargs that modify the build daemon process itself."

    // Only applies to gradle.properties lines starting with org.gradle.jvmargs
    private val jvmArgsLine = Pattern.compile(
        """^org\.gradle\.jvmargs\s*=\s*(.+)$""",
        Pattern.CASE_INSENSITIVE
    )

    private data class DangerousFlag(val pattern: Pattern, val description: String, val risk: RiskLevel)

    private val dangerousFlags = listOf(
        DangerousFlag(
            Pattern.compile("""-javaagent:""", Pattern.CASE_INSENSITIVE),
            "'-javaagent:' loads a Java agent into the build daemon, giving it full access to all classes and memory during the build.",
            RiskLevel.HIGH
        ),
        DangerousFlag(
            Pattern.compile("""--add-opens""", Pattern.CASE_INSENSITIVE),
            "'--add-opens' bypasses Java module encapsulation, allowing reflection into internal JDK APIs.",
            RiskLevel.MEDIUM
        ),
        DangerousFlag(
            Pattern.compile("""--illegal-access=permit""", Pattern.CASE_INSENSITIVE),
            "'--illegal-access=permit' silently allows reflective access to internal JDK APIs (deprecated and removed in JDK 17+).",
            RiskLevel.MEDIUM
        ),
        DangerousFlag(
            Pattern.compile("""-XX:\+DisableExplicitGC""", Pattern.CASE_INSENSITIVE),
            "'-XX:+DisableExplicitGC' disables explicit GC calls, which can cause memory issues in long-running build daemons.",
            RiskLevel.LOW
        ),
        DangerousFlag(
            Pattern.compile("""-agentlib:""", Pattern.CASE_INSENSITIVE),
            "'-agentlib:' loads a native agent into the build daemon with unrestricted native code access.",
            RiskLevel.HIGH
        ),
        DangerousFlag(
            Pattern.compile("""-agentpath:""", Pattern.CASE_INSENSITIVE),
            "'-agentpath:' loads a native agent by filesystem path into the build daemon.",
            RiskLevel.HIGH
        ),
        DangerousFlag(
            Pattern.compile("""-Xbootclasspath""", Pattern.CASE_INSENSITIVE),
            "'-Xbootclasspath' prepends/appends to the bootstrap classloader, allowing replacement of core JDK classes.",
            RiskLevel.HIGH
        )
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (file.name != "gradle.properties") return emptyList()

        val violations = mutableListOf<SecurityViolation>()
        content.lines().forEachIndexed { index, line ->
            val stripped = line.trim()
            if (stripped.startsWith("#")) return@forEachIndexed

            val argsMatcher = jvmArgsLine.matcher(stripped)
            if (!argsMatcher.find()) return@forEachIndexed

            val argsValue = argsMatcher.group(1)
            for (flag in dangerousFlags) {
                if (flag.pattern.matcher(argsValue).find()) {
                    violations.add(
                        SecurityViolation(
                            file = file,
                            line = index + 1,
                            content = stripped,
                            message = "Dangerous JVM arg in org.gradle.jvmargs: ${flag.description}",
                            riskLevel = flag.risk,
                            checkId = id
                        )
                    )
                }
            }
        }
        return violations
    }
}
