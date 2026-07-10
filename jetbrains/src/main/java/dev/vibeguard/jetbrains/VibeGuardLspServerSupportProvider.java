package dev.vibeguard.jetbrains;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.platform.lsp.api.LspServerSupportProvider;
import org.jetbrains.annotations.NotNull;

/** Starts one project-wide VibeGuard LSP process only for supported source files. */
public final class VibeGuardLspServerSupportProvider implements LspServerSupportProvider {
  @Override
  public void fileOpened(
      @NotNull Project project,
      @NotNull VirtualFile file,
      @NotNull LspServerStarter serverStarter
  ) {
    if (VibeGuardLspServerDescriptor.isSupported(file)) {
      serverStarter.ensureServerStarted(new VibeGuardLspServerDescriptor(project));
    }
  }
}
