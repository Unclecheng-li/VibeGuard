package dev.vibeguard.jetbrains.ui;

import com.intellij.openapi.Disposable;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileEditor.FileEditorManager;
import com.intellij.openapi.fileEditor.OpenFileDescriptor;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.Messages;
import com.intellij.openapi.vfs.LocalFileSystem;
import com.intellij.openapi.vfs.VirtualFile;
import com.intellij.ide.util.PropertiesComponent;
import com.intellij.ui.components.JBLabel;
import com.intellij.ui.components.JBList;
import com.intellij.util.ui.JBUI;
import dev.vibeguard.jetbrains.lsp.VibeGuardLspBridge;
import org.jetbrains.annotations.NotNull;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CompletableFuture;

/** ToolWindow UI for user-initiated L3 reviews of the current file. */
public final class VibeGuardPanel extends JPanel implements Disposable {
  private final Project project;
  private final VibeGuardLspBridge bridge;
  private final JButton scanButton = new JButton("Scan with AI");
  private final JButton cancelButton = new JButton("Cancel");
  private final JButton openButton = new JButton("Open");
  private final JButton fixButton = new JButton("Review & Apply Fix");
  private final JButton ignoreButton = new JButton("Ignore");
  private final JBLabel status = new JBLabel("Ready");
  private final JBLabel summary = new JBLabel("Open a supported file to run an AI deep scan.");
  private final DefaultListModel<VibeGuardLspBridge.ReviewFinding> findings = new DefaultListModel<>();
  private final JBList<VibeGuardLspBridge.ReviewFinding> findingList = new JBList<>(findings);
  private CompletableFuture<?> activeRequest;
  private VirtualFile reviewedFile;
  private boolean reviewInProgress;

  public VibeGuardPanel(@NotNull Project project) {
    super(new BorderLayout(0, JBUI.scale(8)));
    this.project = project;
    this.bridge = new VibeGuardLspBridge(project);
    setBorder(JBUI.Borders.empty(8));

    JPanel controls = new JPanel(new FlowLayout(FlowLayout.LEFT, JBUI.scale(6), 0));
    controls.setOpaque(false);
    controls.add(scanButton);
    controls.add(cancelButton);
    controls.add(openButton);
    controls.add(fixButton);
    controls.add(ignoreButton);
    add(controls, BorderLayout.NORTH);

    JPanel content = new JPanel(new BorderLayout(0, JBUI.scale(6)));
    content.setOpaque(false);
    content.add(status, BorderLayout.NORTH);
    content.add(summary, BorderLayout.CENTER);
    findingList.setCellRenderer(new FindingRenderer());
    findingList.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
    JScrollPane scrollPane = new JScrollPane(findingList);
    scrollPane.setBorder(BorderFactory.createEmptyBorder());
    content.add(scrollPane, BorderLayout.SOUTH);
    add(content, BorderLayout.CENTER);

    scanButton.addActionListener(event -> scan(false));
    cancelButton.addActionListener(event -> cancelReview());
    openButton.addActionListener(event -> openSelected());
    fixButton.addActionListener(event -> applySelectedFix());
    ignoreButton.addActionListener(event -> ignoreSelected());
    findingList.addListSelectionListener(event -> updateActions());
    findingList.addMouseListener(new MouseAdapter() {
      @Override
      public void mouseClicked(MouseEvent event) {
        if (event.getClickCount() == 2) {
          openSelected();
        }
      }
    });
    updateActions();
  }

  @Override
  public void dispose() {
    if (reviewInProgress && reviewedFile != null) {
      bridge.cancelReview(reviewedFile);
    }
    if (activeRequest != null) {
      activeRequest.cancel(true);
    }
  }

  private void scan(boolean remoteApproved) {
    VirtualFile file = activeFile();
    if (file == null) {
      status.setText("Open a supported file before starting an AI deep scan.");
      return;
    }
    reviewedFile = file;
    findings.clear();
    reviewInProgress = true;
    setScanning(true, "Starting VibeGuard language server review...");
    activeRequest = bridge.review(file, remoteApproved);
    activeRequest.whenComplete((value, error) -> ApplicationManager.getApplication().invokeLater(() -> {
      if (project.isDisposed()) {
        return;
      }
      activeRequest = null;
      reviewInProgress = false;
      setScanning(false, "");
      if (error != null) {
        status.setText("AI deep scan could not start.");
        summary.setText(error.getCause() == null ? error.getMessage() : error.getCause().getMessage());
        return;
      }
      VibeGuardLspBridge.ReviewResult result = (VibeGuardLspBridge.ReviewResult) value;
      if ("consentRequired".equals(result.status())) {
        requestRemoteConsent(file, result);
        return;
      }
      renderResult(result);
    }));
  }

  private void requestRemoteConsent(@NotNull VirtualFile file, @NotNull VibeGuardLspBridge.ReviewResult result) {
    if (remoteReviewApproved(result)) {
      scan(true);
      return;
    }
    int choice = Messages.showYesNoDialog(
        project,
        "VibeGuard will send the current file to " + result.provider() + " at " + result.endpoint() + " for AI security review. "
            + "Secret-like values are redacted, but the review may contain proprietary source code.",
        "Allow VibeGuard Remote Review",
        "Allow",
        "Cancel",
        Messages.getWarningIcon()
    );
    if (choice == Messages.YES) {
      PropertiesComponent.getInstance(project).setValue(remoteApprovalKey(result), true);
      scan(true);
    } else {
      status.setText("Remote review was not started.");
      summary.setText("Provider: " + result.provider() + " - Model: " + result.model());
    }
  }

  private void cancelReview() {
    if (!reviewInProgress || reviewedFile == null) {
      return;
    }
    cancelButton.setEnabled(false);
    status.setText("Cancelling AI deep scan...");
    bridge.cancelReview(reviewedFile).whenComplete((cancelled, error) -> ApplicationManager.getApplication().invokeLater(() -> {
      if (project.isDisposed() || Boolean.TRUE.equals(cancelled)) {
        return;
      }
      status.setText("Could not cancel the AI deep scan.");
      if (reviewInProgress) {
        cancelButton.setEnabled(true);
      }
    }));
  }

  private boolean remoteReviewApproved(@NotNull VibeGuardLspBridge.ReviewResult result) {
    return PropertiesComponent.getInstance(project).getBoolean(remoteApprovalKey(result), false);
  }

  private static @NotNull String remoteApprovalKey(@NotNull VibeGuardLspBridge.ReviewResult result) {
    return "vibeguard.l3.remoteReviewApproved." + result.provider() + "." + Integer.toUnsignedString(result.endpoint().hashCode());
  }

  private void renderResult(@NotNull VibeGuardLspBridge.ReviewResult result) {
    if (result.stale()) {
      status.setText("The file changed while the review was running.");
      summary.setText("Result discarded. Run the scan again for the current document version.");
      return;
    }
    if ("notConfigured".equals(result.status())) {
      status.setText("L3 is not configured.");
      summary.setText("Set the selected provider credential through the VibeGuard LSP environment or OS credential store.");
      return;
    }
    if ("failed".equals(result.status())) {
      status.setText("AI deep scan failed.");
      summary.setText("Check the VibeGuard language server output for details.");
      return;
    }
    if ("cancelled".equals(result.status())) {
      status.setText("AI deep scan cancelled.");
      summary.setText("No L3 findings were applied.");
      return;
    }
    findings.clear();
    for (VibeGuardLspBridge.ReviewFinding finding : result.findings()) {
      findings.addElement(finding);
    }
    status.setText("Complete - " + result.status());
    summary.setText(String.format("%s - %s - %.2fs - %d finding%s", result.provider(), result.model(), result.elapsedMs() / 1000.0,
        result.findings().size(), result.findings().size() == 1 ? "" : "s"));
    updateActions();
  }

  private void openSelected() {
    VibeGuardLspBridge.ReviewFinding finding = findingList.getSelectedValue();
    if (finding == null) {
      return;
    }
    VirtualFile file = LocalFileSystem.getInstance().findFileByNioFile(Path.of(finding.file()));
    if (file != null) {
      new OpenFileDescriptor(project, file, Math.max(0, finding.line() - 1), Math.max(0, finding.column() - 1)).navigate(true);
    }
  }

  private void applySelectedFix() {
    VibeGuardLspBridge.ReviewFinding finding = findingList.getSelectedValue();
    if (finding == null || !finding.hasFix() || reviewedFile == null) {
      return;
    }
    setScanning(true, "Waiting for L3 fix confirmation...");
    activeRequest = bridge.applyL3Fix(reviewedFile, finding.id());
    completeAction("L3 replacement was applied after review.", "VibeGuard could not apply the L3 replacement.");
  }

  private void ignoreSelected() {
    VibeGuardLspBridge.ReviewFinding finding = findingList.getSelectedValue();
    if (finding == null || reviewedFile == null) {
      return;
    }
    setScanning(true, "Saving ignore rule...");
    activeRequest = bridge.ignoreFinding(reviewedFile, finding.id());
    completeAction("Ignore rule saved for this finding.", "VibeGuard could not save the ignore rule.");
  }

  private void completeAction(@NotNull String success, @NotNull String failure) {
    activeRequest.whenComplete((ignored, error) -> ApplicationManager.getApplication().invokeLater(() -> {
      if (project.isDisposed()) {
        return;
      }
      activeRequest = null;
      setScanning(false, "");
      if (error == null) {
        status.setText(success);
      } else {
        status.setText(failure);
      }
    }));
  }

  private VirtualFile activeFile() {
    return FileEditorManager.getInstance(project).getSelectedFiles().length == 0
        ? null
        : FileEditorManager.getInstance(project).getSelectedFiles()[0];
  }

  private void setScanning(boolean scanning, @NotNull String detail) {
    scanButton.setEnabled(!scanning);
    cancelButton.setEnabled(scanning && reviewInProgress && reviewedFile != null);
    openButton.setEnabled(!scanning && findingList.getSelectedValue() != null);
    fixButton.setEnabled(!scanning && findingList.getSelectedValue() != null && findingList.getSelectedValue().hasFix());
    ignoreButton.setEnabled(!scanning && findingList.getSelectedValue() != null);
    if (scanning) {
      status.setText(detail);
    }
  }

  private void updateActions() {
    boolean hasSelection = findingList.getSelectedValue() != null && activeRequest == null;
    openButton.setEnabled(hasSelection);
    fixButton.setEnabled(hasSelection && findingList.getSelectedValue().hasFix());
    ignoreButton.setEnabled(hasSelection);
  }

  private static final class FindingRenderer extends DefaultListCellRenderer {
    @Override
    public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean selected, boolean focus) {
      VibeGuardLspBridge.ReviewFinding finding = (VibeGuardLspBridge.ReviewFinding) value;
      String text = "<html><b>" + escape(finding.severity().toUpperCase()) + " · " + escape(finding.ruleId()) + "</b><br>"
          + escape(finding.message()) + "<br><span style='color:gray'>" + escape(finding.file()) + ":" + finding.line() + "</span></html>";
      return super.getListCellRendererComponent(list, text, index, selected, focus);
    }

    private static String escape(String value) {
      return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
  }
}
