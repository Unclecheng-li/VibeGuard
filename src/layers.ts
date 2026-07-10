import type { DetectionLayer, Finding } from "./types";
import { uniqueFindings } from "./utils";

export interface ExecutedLayers {
  l1?: boolean;
  l2?: boolean;
  l3?: boolean;
}

export function isLayerExecuted(layer: DetectionLayer, executed: ExecutedLayers): boolean {
  if (layer === "L1") {
    return Boolean(executed.l1);
  }
  if (layer === "L2") {
    return Boolean(executed.l2);
  }
  return Boolean(executed.l3);
}

export function mergeFindingsForExecutedLayers(
  existing: Finding[],
  next: Finding[],
  executed: ExecutedLayers,
  replaceAll = false
): Finding[] {
  if (replaceAll) {
    return uniqueFindings(next);
  }

  const kept = existing.filter((finding) => !isLayerExecuted(finding.detection_layer, executed));
  return uniqueFindings([...kept, ...next]);
}
