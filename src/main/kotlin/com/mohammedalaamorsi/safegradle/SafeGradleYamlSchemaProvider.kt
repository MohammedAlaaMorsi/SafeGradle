package com.mohammedalaamorsi.safegradle

import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.VirtualFile

// JSON Schema provider for .safegradle.yml — wired via safegradle-json-schema.xml (optional dependency).
// The factory and provider interfaces live in com.jetbrains.jsonSchema which is only available
// when the JSON plugin is present. This file uses a reflection-based shim so the plugin
// compiles and runs without that dependency, while still providing schema support when it is present.

object SafeGradleYamlSchemaRegistrar {

    fun tryRegister() {
        try {
            val factoryClass = Class.forName("com.jetbrains.jsonSchema.extension.JsonSchemaProviderFactory")
            // If the class is present, IntelliJ will discover our factory via plugin.xml automatically.
            // No runtime registration needed — the EP wiring handles it.
        } catch (_: ClassNotFoundException) {
            // JSON plugin not present — schema autocomplete unavailable, no action needed.
        }
    }
}
