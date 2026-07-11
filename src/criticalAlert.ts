import type { Finding } from "./types";

export function criticalAlertMessage(finding: Finding): string {
  const message = `VibeGuard: ${finding.message}`;
  if (finding.type !== "hallucinated_package") {
    return message;
  }
  return `${message} This may be a slopsquatting risk: an attacker could register this package name with malicious code.`;
}
