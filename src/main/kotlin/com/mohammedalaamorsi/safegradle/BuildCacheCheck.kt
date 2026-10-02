package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

class BuildCacheCheck : SecurityCheck {
    override val id = "build_cache"
    override val name = "Remote Build Cache Safety"
    override val description = "Flags remote build caches that any machine can push to, or that skip TLS validation — both allow cache poisoning."

    // Literal `true` only: `isPush = System.getenv("CI") != null` is the recommended, safe form
    private val unconditionalPush = Regex("""^\s*(isPush|push)\s*=\s*true\b""")
    private val pushCall = Regex("""^\s*setPush\s*\(\s*true\s*\)""")
    private val untrustedServer = Regex("""\b(isAllowUntrustedServer|allowUntrustedServer)\s*=\s*true\b|setAllowUntrustedServer\s*\(\s*true\s*\)""")

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (!file.name.startsWith("settings.gradle")) return emptyList()
        val violations = mutableListOf<SecurityViolation>()
        var depth = 0
        var remoteDepth = -1  // brace depth at which the current remote { } block opened

        content.lines().forEachIndexed { index, rawLine ->
            val line = SecurityUtils.stripComments(rawLine)
            if (remoteDepth < 0 && Regex("""\bremote\s*(<[^>]*>|\([^)]*\))?\s*\{""").containsMatchIn(line)) {
                remoteDepth = depth
            }
            val inRemote = remoteDepth >= 0

            if (inRemote && (unconditionalPush.containsMatchIn(line) || pushCall.containsMatchIn(line))) {
                violations += SecurityViolation(
                    file = file, line = index + 1, content = rawLine.trim(), riskLevel = RiskLevel.MEDIUM, checkId = id,
                    message = "Remote build cache push is enabled unconditionally — any developer machine can poison the shared cache " +
                        "with tampered outputs. Restrict pushing to CI, e.g. isPush = System.getenv(\"CI\") != null."
                )
            }
            if (untrustedServer.containsMatchIn(line)) {
                violations += SecurityViolation(
                    file = file, line = index + 1, content = rawLine.trim(), riskLevel = RiskLevel.HIGH, checkId = id,
                    message = "Build cache allows an untrusted server — TLS certificate validation is disabled, so anyone on the " +
                        "network path can serve poisoned build outputs."
                )
            }

            depth += line.count { it == '{' } - line.count { it == '}' }
            if (inRemote && depth <= remoteDepth) remoteDepth = -1
        }
        return violations
    }
}
