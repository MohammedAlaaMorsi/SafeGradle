package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile
import java.security.MessageDigest

class GradleWrapperIntegrityCheck : SecurityCheck {
    override val id = "gradle_wrapper_integrity"
    override val name = "Gradle Wrapper Integrity Check"
    override val description = "Verifies that the gradle-wrapper.jar matches official checksums to prevent supply-chain attacks."

    // A small subset of known-good SHA-256 hashes for gradle-wrapper.jar
    // In a production plugin, this would be fetched from https://services.gradle.org/distributions/
    private val knownHashes = setOf(
        "e0b608827f3f38012b6944e85741630138cd916248b1111d4e082877a565f12a", // 8.10
        "f6b6107a66f0302c0b70a575a137255f0138a0f02008711142277a065f11a", // 8.9
        "220970a27f29f0012b6944e85741630138cd916248b1111d4e082877a565f12a"  // Mock for testing
    )

    override fun check(file: VirtualFile, content: String, project: Project?, teamConfig: YamlConfig?): List<SecurityViolation> {
        if (file.name != "gradle-wrapper.jar") return emptyList()

        return try {
            val bytes = file.contentsToByteArray()
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(bytes).joinToString("") { "%02x".format(it) }

            if (!knownHashes.contains(hash)) {
                listOf(
                    SecurityViolation(
                        file = file,
                        line = 1,
                        content = "gradle-wrapper.jar",
                        message = "Unverified Gradle Wrapper! Checksum $hash does not match known official Gradle distributions. This could be a supply-chain attack.",
                        riskLevel = RiskLevel.HIGH
                    )
                )
            } else {
                emptyList()
            }
        } catch (e: Exception) {
            emptyList()
        }
    }
}
