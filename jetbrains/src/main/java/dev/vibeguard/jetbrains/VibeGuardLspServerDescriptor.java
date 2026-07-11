package dev.vibeguard.jetbrains;

import com.intellij.execution.configurations.GeneralCommandLine;
import com.intellij.openapi.application.PathManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.platform.lsp.api.ProjectWideLspServerDescriptor;
import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import java.util.Set;

/** Describes the default Node.js server and opt-in native Rust L1 preview. */
final class VibeGuardLspServerDescriptor extends ProjectWideLspServerDescriptor {
  private static final String SERVER_RESOURCE = "lsp/vibeguard-lsp.js";
  private static final Set<String> SUPPORTED_EXTENSIONS = Set.of(
      "cjs", "go", "gradle", "groovy", "java", "js", "json", "jsx", "kt", "kts", "mjs",
      "py", "rs", "toml", "ts", "tsx", "xml"
  );

  VibeGuardLspServerDescriptor(@NotNull Project project) {
    super(project, "VibeGuard");
  }

  static boolean isSupported(@NotNull VirtualFile file) {
    if (file.isDirectory()) {
      return false;
    }
    String extension = file.getExtension();
    return extension != null && SUPPORTED_EXTENSIONS.contains(extension.toLowerCase(Locale.ROOT));
  }

  @Override
  public boolean isSupportedFile(@NotNull VirtualFile file) {
    return isSupported(file);
  }

  @Override
  public @NotNull GeneralCommandLine createCommandLine() {
    String nativePath = nativeServerPath();
    if (!nativePath.isBlank()) {
      return new GeneralCommandLine(nativePath, "--stdio");
    }
    return new GeneralCommandLine(nodeExecutable(), serverPath(), "--stdio");
  }

  private static String nativeServerPath() {
    return configuredValue("VIBEGUARD_NATIVE_LSP_PATH", "vibeguard.native.lsp.path", "");
  }

  private static String nodeExecutable() {
    return configuredValue("VIBEGUARD_NODE_PATH", "vibeguard.node.path", "node");
  }

  private static String serverPath() {
    String configuredPath = configuredValue("VIBEGUARD_LSP_PATH", "vibeguard.lsp.path", "");
    return configuredPath.isBlank() ? extractBundledServer().toString() : configuredPath;
  }

  private static String configuredValue(String environmentVariable, String systemProperty, String fallback) {
    String configured = System.getProperty(systemProperty);
    if (configured == null || configured.isBlank()) {
      configured = System.getenv(environmentVariable);
    }
    return configured == null || configured.isBlank() ? fallback : configured.trim();
  }

  private static Path extractBundledServer() {
    Path target = Path.of(PathManager.getSystemPath(), "vibeguard", "lsp", "vibeguard-lsp.js");
    try (InputStream source = VibeGuardLspServerDescriptor.class.getClassLoader().getResourceAsStream(SERVER_RESOURCE)) {
      if (source == null) {
        throw new IllegalStateException("VibeGuard LSP bundle is missing from the plugin distribution.");
      }
      Files.createDirectories(target.getParent());
      Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
      return target;
    } catch (IOException error) {
      throw new IllegalStateException("Unable to prepare the VibeGuard LSP server.", error);
    }
  }
}
