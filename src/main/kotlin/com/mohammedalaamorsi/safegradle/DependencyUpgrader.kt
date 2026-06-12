package com.mohammedalaamorsi.safegradle

/**
 * Rewrites the version token of a dependency declaration line to a fixed version.
 * Pure string logic so it can be unit tested; returns null when the line cannot be
 * upgraded safely (interpolated versions, version.ref indirection, already fixed, no match).
 */
object DependencyUpgrader {

    // "group:artifact:version" inside matching quotes; version must be a literal (no $ interpolation)
    private val gavPattern = Regex("""(["'])([a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+):([^"'$]+)\1""")

    // TOML table entry: version = "x.y.z" (version.ref handled separately)
    private val tomlVersionPattern = Regex("""(version\s*=\s*")([^"$]+)(")""")

    fun upgradeLine(line: String, fixVersion: String): String? {
        if (line.contains("version.ref")) return null

        gavPattern.find(line)?.let { m ->
            val (quote, module, version) = m.destructured
            if (version == fixVersion) return null
            return line.replaceRange(m.range, "$quote$module:$fixVersion$quote")
        }

        tomlVersionPattern.find(line)?.let { m ->
            if (m.groupValues[2] == fixVersion) return null
            return line.replaceRange(m.range, "${m.groupValues[1]}$fixVersion${m.groupValues[3]}")
        }

        return null
    }
}
