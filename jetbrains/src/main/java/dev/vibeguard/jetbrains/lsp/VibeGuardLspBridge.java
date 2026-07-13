package dev.vibeguard.jetbrains.lsp;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.platform.lsp.api.LspServer;
import com.intellij.platform.lsp.api.LspServerManager;
import com.intellij.platform.lsp.api.LspServerState;
import com.intellij.util.concurrency.AppExecutorUtil;
import dev.vibeguard.jetbrains.VibeGuardLspServerSupportProvider;
import org.eclipse.lsp4j.ExecuteCommandParams;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/** Sends a manual L3 review request through the public IntelliJ LSP API. */
public final class VibeGuardLspBridge {
  public static final String MANUAL_REVIEW_COMMAND = "vibeguard.scanWithAi";
  public static final String CANCEL_MANUAL_REVIEW_COMMAND = "vibeguard.cancelAiScan";
  public static final String APPLY_L3_FIX_COMMAND = "vibeguard.applyL3Fix";
  public static final String IGNORE_FINDING_COMMAND = "vibeguard.ignoreFinding";
  private static final int REQUEST_TIMEOUT_MS = 15_000;

  private final Project project;

  public VibeGuardLspBridge(@NotNull Project project) {
    this.project = project;
  }

  public @NotNull CompletableFuture<ReviewResult> review(@NotNull VirtualFile file, boolean remoteApproved) {
    return CompletableFuture.supplyAsync(() -> requestReview(file, remoteApproved), AppExecutorUtil.getAppExecutorService());
  }

  public @NotNull CompletableFuture<Void> applyL3Fix(@NotNull VirtualFile file, @NotNull String findingId) {
    return CompletableFuture.supplyAsync(() -> sendRequest(new ExecuteCommandParams(
        APPLY_L3_FIX_COMMAND,
        List.of(Map.of("findingId", findingId, "uri", serverUri(file)))
    )), AppExecutorUtil.getAppExecutorService()).thenApply(ignored -> null);
  }

  public @NotNull CompletableFuture<Void> ignoreFinding(@NotNull VirtualFile file, @NotNull String findingId) {
    return CompletableFuture.supplyAsync(() -> sendRequest(new ExecuteCommandParams(
        IGNORE_FINDING_COMMAND,
        List.of(Map.of("findingId", findingId, "scope", "line"))
    )), AppExecutorUtil.getAppExecutorService()).thenApply(ignored -> null);
  }

  public @NotNull CompletableFuture<Boolean> cancelReview(@NotNull VirtualFile file) {
    return CompletableFuture.supplyAsync(() -> {
      Object response = sendRequest(new ExecuteCommandParams(
          CANCEL_MANUAL_REVIEW_COMMAND,
          List.of(Map.of("uri", serverUri(file)))
      ));
      return response instanceof Map<?, ?> result && Boolean.TRUE.equals(result.get("cancelled"));
    }, AppExecutorUtil.getAppExecutorService());
  }

  private @NotNull ReviewResult requestReview(@NotNull VirtualFile file, boolean remoteApproved) {
    String uri = serverUri(file);
    Map<String, Object> argument = new LinkedHashMap<>();
    argument.put("uri", uri);
    argument.put("remoteApproved", remoteApproved);
    ExecuteCommandParams params = new ExecuteCommandParams(MANUAL_REVIEW_COMMAND, List.of(argument));
    Object response = sendRequest(params);
    return ReviewResult.from(response);
  }

  private @NotNull String serverUri(@NotNull VirtualFile file) {
    return runningServer().getDocumentIdentifier(file).getUri();
  }

  private @NotNull Object sendRequest(@NotNull ExecuteCommandParams params) {
    return runningServer().sendRequestSync(
        REQUEST_TIMEOUT_MS,
        languageServer -> languageServer.getWorkspaceService().executeCommand(params)
    );
  }

  private @NotNull LspServer runningServer() {
    LspServerManager manager = LspServerManager.getInstance(project);
    manager.startServersIfNeeded(VibeGuardLspServerSupportProvider.class);
    return manager.getServersForProvider(VibeGuardLspServerSupportProvider.class).stream()
        .filter(candidate -> candidate.getState() == LspServerState.Running)
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("VibeGuard language server is starting. Try the scan again in a moment."));
  }

  public record ReviewFinding(
      @NotNull String id,
      @NotNull String severity,
      @NotNull String ruleId,
      @NotNull String message,
      @NotNull String file,
      int line,
      int column,
      boolean hasFix
  ) {
  }

  public record ReviewResult(
      @NotNull String status,
      @NotNull String provider,
      @NotNull String model,
      @NotNull String endpoint,
      long elapsedMs,
      boolean stale,
      @NotNull List<ReviewFinding> findings
  ) {
    private static @NotNull ReviewResult from(Object value) {
      Map<?, ?> response = map(value);
      Map<?, ?> outcome = map(response.get("outcome"));
      List<ReviewFinding> findings = new ArrayList<>();
      Object rawFindings = outcome.get("findings");
      if (rawFindings instanceof List<?> entries) {
        for (Object entry : entries) {
          Map<?, ?> finding = map(entry);
          findings.add(new ReviewFinding(
              string(finding.get("id")),
              string(finding.get("severity")),
              string(finding.get("detection_rule")),
              string(finding.get("message")),
              string(finding.get("file")),
              number(finding.get("line")),
              number(finding.get("column")),
              finding.get("fix") != null
          ));
        }
      }
      return new ReviewResult(
          string(outcome.get("status")),
          string(outcome.get("provider")),
          string(outcome.get("model")),
          string(response.get("endpoint")),
          number(outcome.get("elapsedMs")),
          Boolean.TRUE.equals(response.get("stale")),
          List.copyOf(findings)
      );
    }

    private static @NotNull Map<?, ?> map(Object value) {
      return value instanceof Map<?, ?> map ? map : Map.of();
    }

    private static @NotNull String string(Object value) {
      return value instanceof String text ? text : "";
    }

    private static int number(Object value) {
      return value instanceof Number number ? number.intValue() : 0;
    }
  }
}
