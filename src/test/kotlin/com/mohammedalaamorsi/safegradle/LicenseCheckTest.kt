package com.mohammedalaamorsi.safegradle

import junit.framework.TestCase

/**
 * Covers the offline parts of LicenseCheck — POM parsing and copyleft classification.
 * The lookup itself needs Maven Central, so it is exercised through the companion cache instead.
 */
class LicenseCheckTest : TestCase() {

    private val apachePom = """
        <project>
          <licenses>
            <license>
              <name>Apache License, Version 2.0</name>
              <url>https://www.apache.org/licenses/LICENSE-2.0.txt</url>
            </license>
          </licenses>
        </project>
    """.trimIndent()

    private val gplPom = """
        <project>
          <licenses>
            <license><name>GNU General Public License, Version 2</name></license>
          </licenses>
        </project>
    """.trimIndent()

    // ─── licenceNames ─────────────────────────────────────────────────────

    fun `test reads licence name from pom`() {
        assertEquals(listOf("Apache License, Version 2.0"), LicenseCheck.licenceNames(apachePom))
    }

    fun `test returns empty list when pom has no licences`() {
        assertTrue(LicenseCheck.licenceNames("<project><artifactId>x</artifactId></project>").isEmpty())
    }

    // ─── parentCoords ─────────────────────────────────────────────────────

    fun `test reads parent coordinates from pom`() {
        val pom = """
            <project>
              <parent>
                <groupId>org.apache</groupId>
                <artifactId>apache</artifactId>
                <version>28</version>
              </parent>
            </project>
        """.trimIndent()
        val (group, artifact, version) = LicenseCheck.parentCoords(pom)!!
        assertEquals("org.apache", group)
        assertEquals("apache", artifact)
        assertEquals("28", version)
    }

    fun `test returns null when pom has no parent`() {
        assertNull(LicenseCheck.parentCoords("<project><artifactId>x</artifactId></project>"))
    }

    // ─── copyleftKind ─────────────────────────────────────────────────────

    fun `test classifies gpl as medium-risk copyleft`() {
        assertEquals("GPL", LicenseCheck.copyleftKind("GNU General Public License, Version 2"))
    }

    fun `test classifies agpl as copyleft`() {
        assertEquals("AGPL", LicenseCheck.copyleftKind("GNU Affero General Public License v3.0"))
    }

    fun `test classifies sspl as copyleft`() {
        assertEquals("SSPL", LicenseCheck.copyleftKind("Server Side Public License, Version 1"))
    }

    fun `test ignores lesser gpl`() {
        assertNull(LicenseCheck.copyleftKind("GNU Lesser General Public License v2.1"))
    }

    fun `test ignores apache licence`() {
        assertNull(LicenseCheck.copyleftKind("Apache License, Version 2.0"))
    }

    fun `test ignores gpl with classpath exception`() {
        assertNull(LicenseCheck.copyleftKind("GNU General Public License, Version 2 with the GNU Classpath Exception"))
    }

    fun `test ignores dual licence that includes a permissive option`() {
        assertNull(LicenseCheck.copyleftKind("Apache License, Version 2.0 / GNU Affero General Public License v3.0"))
    }

    fun `test reports the strongest licence in a dual copyleft grant`() {
        assertEquals("AGPL", LicenseCheck.copyleftKind("GNU General Public License, Version 2 / GNU Affero General Public License v3.0"))
    }
}