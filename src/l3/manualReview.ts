import { scanSourceFile } from "../scanner";
import type { L3ReviewOutcome, LlmProvider, ScanOptions, SourceFile } from "../types";
import { defaultLlmModel, LlmSemanticAnalyzer } from "./llm";

export interface ManualL3ReviewRequest {
  source: SourceFile;
  provider: LlmProvider;
  model?: string;
  analyzer?: LlmSemanticAnalyzer;
  remoteApproved: boolean;
  scanOptions?: Omit<ScanOptions, "detectionLayers" | "includeL3" | "l3Analyzer">;
  timestamp?: number;
}

/**
 * Runs a single, user-initiated L3 review while retaining scanner filtering,
 * ignore rules, and finding shape. Remote review is explicitly opt-in.
 */
export async function runManualL3Review(request: ManualL3ReviewRequest): Promise<L3ReviewOutcome> {
  const startedAt = Date.now();
  const model = request.model ?? defaultLlmModel(request.provider);
  if (request.provider !== "local" && !request.remoteApproved) {
    return {
      status: "consentRequired",
      findings: [],
      provider: request.provider,
      model,
      elapsedMs: Date.now() - startedAt,
      errorCode: "consentRequired",
      filesScanned: 0
    };
  }
  if (!request.analyzer) {
    return {
      status: "notConfigured",
      findings: [],
      provider: request.provider,
      model,
      elapsedMs: Date.now() - startedAt,
      errorCode: "notConfigured",
      filesScanned: 0
    };
  }

  const timestamp = request.timestamp ?? Date.now();
  let review: L3ReviewOutcome | undefined;
  const result = await scanSourceFile(request.source, {
    ...request.scanOptions,
    detectionLayers: { l1: false, l2: false, l3: true },
    l3Analyzer: {
      analyze: async (source, scanTimestamp) => {
        review = await request.analyzer!.review(source, scanTimestamp);
        return review.findings;
      }
    },
    now: timestamp
  });

  const outcome = review ?? {
    status: "failed" as const,
    findings: [],
    provider: request.provider,
    model: defaultLlmModel(request.provider),
    elapsedMs: Date.now() - startedAt,
    errorCode: "remoteFailed" as const,
    filesScanned: 0
  };
  return {
    ...outcome,
    findings: result.findings,
    elapsedMs: result.elapsedMs,
    filesScanned: outcome.status === "cancelled" ? 0 : 1
  };
}
