package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

class DependencyVerificationCheck : SecurityCheck {
    override val id = "dependency_verification"
    override val name = "Dependency Verification"
    override val description = "Checks that Gradle dependency verification (gradle/verification-metadata.xml) is enabled and not weakened."

    // Do NOT auto-run the generator: --write-verification-metadata executes the (possibly untrusted) build scripts.
    private val generateHint = "Generate it once you trust the build: ./gradlew --write-verification-metadata sha256 help"

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> = when {
        file.name == "verification-metadata.xml" -> checkMetadata(file, content)
        file.name.startsWith("settings.gradle") -> checkPresence(file)
        else -> emptyList()
    }

    private fun checkPresence(settingsFile: VirtualFile): List<SecurityViolation> {
        val root = settingsFile.parent ?: return emptyList()
        // Only the root build (the one with a wrapper) owns verification metadata; buildSrc/included builds share it
        if (root.findChild("gradlew") == null && root.findFileByRelativePath("gradle/wrapper") == null) return emptyList()
        if (root.findFileByRelativePath("gradle/verification-metadata.xml") != null) return emptyList()
        return listOf(
            SecurityViolation(
                file = settingsFile, line = 1, content = settingsFile.name, riskLevel = RiskLevel.LOW, checkId = id,
                message = "Dependency verification is not enabled — Gradle will accept any artifact a repository serves, " +
                    "including tampered ones. $generateHint"
            )
        )
    }

    private fun checkMetadata(file: VirtualFile, content: String): List<SecurityViolation> {
        val violations = mutableListOf<SecurityViolation>()
        fun add(line: Int, text: String, level: RiskLevel, msg: String) {
            violations += SecurityViolation(file = file, line = line, content = text, message = msg, riskLevel = level, checkId = id)
        }
        val lines = content.lines()

        lines.forEachIndexed { index, raw ->
            val line = raw.trim()
            if (Regex("""<verify-metadata>\s*false\s*</verify-metadata>""").containsMatchIn(line)) {
                add(index + 1, line, RiskLevel.MEDIUM, "verify-metadata is disabled — POM and Gradle module metadata files are not " +
                    "checked, so a tampered POM can pull in malicious transitive dependencies.")
            }
            // <trust group=".*" regex="true"/> — trusts every artifact, silently disabling verification
            if (line.startsWith("<trust") && line.contains("regex=\"true\"") &&
                Regex("""\b(group|name|file)="\^?\.\*\$?"""").containsMatchIn(line)) {
                add(index + 1, line, RiskLevel.HIGH, "This trust rule matches every artifact — it switches dependency verification off " +
                    "entirely. Narrow it to the specific group or file that needs it.")
            }
        }

        val hasStrong = content.contains("<sha256") || content.contains("<sha512") || content.contains("<pgp")
        if (!hasStrong && (content.contains("<sha1") || content.contains("<md5"))) {
            add(1, file.name, RiskLevel.LOW, "Verification metadata only uses SHA-1/MD5 checksums, which are vulnerable to collision " +
                "attacks. Regenerate with: ./gradlew --write-verification-metadata sha256 help")
        }
        return violations
    }
}
