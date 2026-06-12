package com.mohammedalaamorsi.safegradle

import junit.framework.TestCase

class OsvFixedVersionParsingTest : TestCase() {

    private val sampleJson = """
    {
      "id": "GHSA-xxxx",
      "summary": "Example vulnerability",
      "affected": [
        {
          "package": {"ecosystem": "Maven", "name": "com.squareup.okhttp3:okhttp"},
          "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.11.0"}]}
          ]
        },
        {
          "package": {"ecosystem": "PyPI", "name": "other-package"},
          "ranges": [
            {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}
          ]
        }
      ]
    }
    """.trimIndent()

    fun `test extracts fixed version for matching package`() {
        assertEquals("4.11.0", OsvAdvisoryClient.extractFixedVersion(sampleJson, "com.squareup.okhttp3:okhttp"))
    }

    fun `test ignores fixed versions of other packages`() {
        assertEquals("9.9.9", OsvAdvisoryClient.extractFixedVersion(sampleJson, "other-package"))
    }

    fun `test returns null for unknown package`() {
        assertNull(OsvAdvisoryClient.extractFixedVersion(sampleJson, "com.example:missing"))
    }

    fun `test returns null when no fixed event exists`() {
        val json = """{"affected":[{"package":{"name":"a:b"},"ranges":[{"events":[{"introduced":"0"}]}]}]}"""
        assertNull(OsvAdvisoryClient.extractFixedVersion(json, "a:b"))
    }

    fun `test returns last fixed event when multiple ranges`() {
        val json = """
        {"affected":[{"package":{"name":"a:b"},"ranges":[
          {"events":[{"introduced":"0"},{"fixed":"1.2.0"}]},
          {"events":[{"introduced":"2.0"},{"fixed":"2.5.0"}]}
        ]}]}
        """.trimIndent()
        assertEquals("2.5.0", OsvAdvisoryClient.extractFixedVersion(json, "a:b"))
    }
}
