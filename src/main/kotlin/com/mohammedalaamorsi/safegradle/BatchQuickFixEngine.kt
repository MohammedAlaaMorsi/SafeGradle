package com.mohammedalaamorsi.safegradle

/**
 * Pure fix logic behind "Fix All", kept out of the Swing layer so it can be unit tested.
 */
object BatchQuickFixEngine {

    const val WRAPPER_FILE = "gradle-wrapper.properties"

    /**
     * Returns [line] with the fix for one violation applied, or null if there is no safe automatic fix.
     * Wrapper checksums are whole-file edits — see [fixWrapper].
     */
    fun fixLine(checkId: String, message: String, fixVersion: String?, line: String): String? {
        val fixed = when {
            checkId == "network_activity" && message.startsWith("Insecure HTTP URL") -> line.replace("http://", "https://")
            checkId == "network_activity" && message.startsWith("JCenter") -> line.replaceFirst("jcenter()", "mavenCentral()")
            checkId == "dependency_vulnerability" && fixVersion != null -> DependencyUpgrader.upgradeLine(line, fixVersion)
            else -> null
        }
        return fixed?.takeIf { it != line }
    }

    /** Sets `distributionSha256Sum` in a gradle-wrapper.properties text, replacing any existing value. */
    fun fixWrapper(text: String, checksum: String): String {
        val regex = Regex("""(?m)^distributionSha256Sum\s*=.*$""")
        if (regex.containsMatchIn(text)) return regex.replace(text, "distributionSha256Sum=$checksum")
        val sep = if (text.isEmpty() || text.endsWith("\n")) "" else "\n"
        return "$text${sep}distributionSha256Sum=$checksum\n"
    }

    fun isFixable(v: SecurityViolation): Boolean = when {
        // Lockfiles are generated — hand-editing them breaks resolution; fix the build script instead
        v.file.name.endsWith(".lockfile") -> false
        v.file.name == WRAPPER_FILE -> v.checkId == "gradle_wrapper_integrity" && v.fixVersion != null
        else -> fixLine(v.checkId, v.message, v.fixVersion, v.content) != null
    }
}
