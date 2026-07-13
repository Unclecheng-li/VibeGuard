import org.gradle.api.tasks.Copy
import org.gradle.api.tasks.Exec
import org.gradle.jvm.toolchain.JavaLanguageVersion

plugins {
  java
  id("org.jetbrains.intellij.platform") version "2.18.0"
}

group = "dev.vibeguard"
version = "0.1.2"

repositories {
  mavenCentral()

  intellijPlatform {
    defaultRepositories()
  }
}

dependencies {
  intellijPlatform {
    intellijIdeaUltimate("2025.2.4") {
      useInstaller = false
    }
  }
}

java {
  toolchain {
    languageVersion.set(JavaLanguageVersion.of(17))
  }
}

val rootProjectDir = layout.projectDirectory.dir("..").asFile
val lspBundle = rootProjectDir.resolve("dist/lspServer.js")
val npmExecutable = if (System.getProperty("os.name").startsWith("Windows", ignoreCase = true)) "npm.cmd" else "npm"

val buildVibeGuardLsp by tasks.registering(Exec::class) {
  group = "build"
  description = "Bundles the shared VibeGuard LSP server for the JetBrains plugin."
  workingDir = rootProjectDir
  commandLine(npmExecutable, "run", "build")
  inputs.files(
    fileTree(rootProjectDir) {
      include("src/**")
      include("scripts/build.js")
      include("package.json")
      include("package-lock.json")
      exclude("src/extension.ts")
    }
  )
  outputs.file(lspBundle)
}

tasks.named<Copy>("processResources") {
  dependsOn(buildVibeGuardLsp)
  from(lspBundle) {
    into("lsp")
    rename { "vibeguard-lsp.js" }
  }
  from(rootProjectDir.resolve("dist/tree-sitter")) {
    into("lsp/tree-sitter")
  }
}

intellijPlatform {
  pluginConfiguration {
    ideaVersion {
      sinceBuild = "252"
    }
  }
  publishing {
    token = providers.environmentVariable("JETBRAINS_MARKETPLACE_TOKEN")
    channels = providers.gradleProperty("jetbrainsChannel").map { listOf(it) }.orElse(listOf("default"))
  }
}
