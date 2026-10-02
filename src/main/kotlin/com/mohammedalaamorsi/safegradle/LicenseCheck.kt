package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.net.HttpURLConnection
import java.util.concurrent.ConcurrentHashMap

class LicenseCheck : SecurityCheck {
    override val id = "copyleft_license"
    override val name = "Copyleft Licence Detection"
    override val description = "Flags dependencies under GPL / AGPL / SSPL licences (opt-in: Settings → Tools → SafeGradle, needs Maven Central access)."

    private val scriptDep = Regex("""["']([A-Za-z0-9._-]+):([A-Za-z0-9._-]+):([A-Za-z0-9._+-]+)["']""")
    private val tomlModule = Regex("""\bmodule\s*=\s*"([A-Za-z0-9._-]+):([A-Za-z0-9._-]+)".*?\bversion\s*=\s*"([^"]+)"""")
    private val tomlGroupName = Regex("""\bgroup\s*=\s*"([A-Za-z0-9._-]+)".*?\bname\s*=\s*"([A-Za-z0-9._-]+)".*?\bversion\s*=\s*"([^"]+)"""")

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (project == null || !SafeGradleSettings.getInstance(project).state.enableLicenseLookup) return emptyList()
        val isToml = file.name.endsWith(".toml")
        if (!isToml && !file.name.startsWith("build.gradle")) return emptyList()

        val violations = mutableListOf<SecurityViolation>()
        content.lines().forEachIndexed { index, raw ->
            val line = if (isToml) raw.substringBefore('#') else SecurityUtils.stripComments(raw)
            val m = (if (isToml) tomlModule.find(line) ?: tomlGroupName.find(line) else scriptDep.find(line)) ?: return@forEachIndexed
            val (group, artifact, version) = m.destructured
            val licence = licenceOf(group, artifact, version) ?: return@forEachIndexed
            val copyleft = copyleftKind(licence) ?: return@forEachIndexed
            violations += SecurityViolation(
                file = file, line = index + 1, content = raw.trim(), checkId = id,
                riskLevel = if (copyleft == "GPL") RiskLevel.MEDIUM else RiskLevel.HIGH,
                message = "$group:$artifact:$version is licensed under '$licence' ($copyleft). " +
                    if (copyleft == "GPL") "Distributing a proprietary app that links it may require releasing your source code."
                    else "$copyleft also covers network use — offering the software as a service may require releasing your source code."
            )
        }
        return violations
    }

    companion object {
        // ponytail: in-memory per IDE session; persist to SafeGradleScanCache if repeated cold scans get slow
        private val cache = ConcurrentHashMap<String, String>()  // "g:a:v" -> licence names joined, "" if unknown

        private const val CENTRAL = "https://repo1.maven.org/maven2/"

        fun licenceOf(group: String, artifact: String, version: String): String? {
            val key = "$group:$artifact:$version"
            return cache.getOrPut(key) { resolve(group, artifact, version, depth = 0) ?: "" }.ifEmpty { null }
        }

        // ponytail: follows one parent POM only; deeper inheritance chains report "unknown" (not flagged)
        private fun resolve(group: String, artifact: String, version: String, depth: Int): String? {
            val pom = fetchPom(group, artifact, version) ?: return null
            licenceNames(pom).takeIf { it.isNotEmpty() }?.let { return it.joinToString(" / ") }
            if (depth >= 1) return null
            val (pg, pa, pv) = parentCoords(pom) ?: return null
            return resolve(pg, pa, pv, depth + 1)
        }

        private fun fetchPom(group: String, artifact: String, version: String): String? = try {
            val url = "$CENTRAL${group.replace('.', '/')}/$artifact/$version/$artifact-$version.pom"
            val conn = java.net.URI(url).toURL().openConnection() as HttpURLConnection
            conn.connectTimeout = 5000
            conn.readTimeout = 5000
            if (conn.responseCode == 200) conn.inputStream.bufferedReader().use { it.readText() } else null
        } catch (_: Exception) { null }

        internal fun licenceNames(pom: String): List<String> {
            val block = Regex("""<licenses>(.*?)</licenses>""", RegexOption.DOT_MATCHES_ALL).find(pom)?.groupValues?.get(1) ?: return emptyList()
            return Regex("""<name>\s*(.*?)\s*</name>""", RegexOption.DOT_MATCHES_ALL).findAll(block).map { it.groupValues[1] }.toList()
        }

        internal fun parentCoords(pom: String): Triple<String, String, String>? {
            val parent = Regex("""<parent>(.*?)</parent>""", RegexOption.DOT_MATCHES_ALL).find(pom)?.groupValues?.get(1) ?: return null
            fun tag(t: String) = Regex("""<$t>\s*(.*?)\s*</$t>""").find(parent)?.groupValues?.get(1)
            return Triple(tag("groupId") ?: return null, tag("artifactId") ?: return null, tag("version") ?: return null)
        }

        /**
         * Returns "AGPL", "SSPL" or "GPL" when every licence in [licence] is strong copyleft; null otherwise.
         * Dual-licensed artifacts with any permissive option, LGPL, and GPL + Classpath Exception are not flagged.
         */
        internal fun copyleftKind(licence: String): String? {
            val kinds = licence.split(" / ").map { name ->
                val n = name.lowercase()
                when {
                    "lesser" in n || "lgpl" in n || "library" in n || "classpath" in n -> null
                    "affero" in n || "agpl" in n -> "AGPL"
                    "server side public" in n || "sspl" in n -> "SSPL"
                    "general public" in n || Regex("""\bgpl""").containsMatchIn(n) -> "GPL"
                    else -> null
                }
            }
            if (kinds.any { it == null }) return null
            return kinds.firstOrNull { it != "GPL" } ?: kinds.firstOrNull()
        }
    }
}
