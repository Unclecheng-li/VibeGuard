export function suggestPackageNames(packageName: string, candidates: Iterable<string>, limit = 3): string[] {
  const query = normalizeForSuggestion(packageName);
  const queryLeaf = packageLeaf(query);
  if (!query) {
    return [];
  }

  return [...candidates]
    .map((candidate) => scoreCandidate(query, queryLeaf, candidate))
    .filter((entry): entry is SuggestionScore => entry !== undefined)
    .sort((a, b) => a.score - b.score || a.distance - b.distance || a.candidate.localeCompare(b.candidate))
    .slice(0, limit)
    .map((entry) => entry.candidate);
}

export function suggestionSearchTerms(packageName: string): string[] {
  const normalized = normalizeForSuggestion(packageName);
  const leaf = packageLeaf(normalized);
  return uniqueTerms([
    normalized.slice(0, Math.min(2, normalized.length)),
    normalized.slice(0, prefixLength(normalized)),
    leaf.slice(0, Math.min(2, leaf.length)),
    leaf.slice(0, prefixLength(leaf)),
    trimCommonHallucinationSuffixes(leaf).slice(0, prefixLength(trimCommonHallucinationSuffixes(leaf)))
  ]);
}

interface SuggestionScore {
  candidate: string;
  score: number;
  distance: number;
}

function scoreCandidate(query: string, queryLeaf: string, candidate: string): SuggestionScore | undefined {
  const normalizedCandidate = normalizeForSuggestion(candidate);
  const candidateLeaf = packageLeaf(normalizedCandidate);
  if (!normalizedCandidate || normalizedCandidate === query) {
    return undefined;
  }

  const fullDistance = levenshtein(query, normalizedCandidate);
  const leafDistance = levenshtein(queryLeaf, candidateLeaf);
  const distance = Math.min(fullDistance, leafDistance);
  const maxLeafLength = Math.max(queryLeaf.length, candidateLeaf.length);
  const maxFullLength = Math.max(query.length, normalizedCandidate.length);
  const plausible =
    distance <= Math.max(2, Math.floor(maxLeafLength * 0.35)) ||
    fullDistance <= Math.max(3, Math.floor(maxFullLength * 0.28)) ||
    normalizedCandidate.includes(query) ||
    query.includes(normalizedCandidate) ||
    candidateLeaf.includes(queryLeaf) ||
    queryLeaf.includes(candidateLeaf);
  if (!plausible) {
    return undefined;
  }

  const substringBonus =
    normalizedCandidate.includes(query) ||
    query.includes(normalizedCandidate) ||
    candidateLeaf.includes(queryLeaf) ||
    queryLeaf.includes(candidateLeaf)
      ? -0.35
      : 0;
  const prefixBonus = normalizedCandidate.startsWith(query.slice(0, 3)) || candidateLeaf.startsWith(queryLeaf.slice(0, 3)) ? -0.15 : 0;
  const score = distance / Math.max(1, maxLeafLength) + fullDistance / Math.max(1, maxFullLength) + substringBonus + prefixBonus;
  return {
    candidate,
    score,
    distance
  };
}

function normalizeForSuggestion(value: string): string {
  return value.trim().toLowerCase().replace(/_/g, "-");
}

function packageLeaf(value: string): string {
  const parts = value.split(/[/:]/).filter(Boolean);
  return parts[parts.length - 1] ?? value;
}

function trimCommonHallucinationSuffixes(value: string): string {
  return value.replace(/(?:-?(?:secure|security|auth|guard|middleware|utils?|client|manager|plugin|plus|pro|extra|magic))+$/i, "");
}

function prefixLength(value: string): number {
  if (value.length <= 2) {
    return value.length;
  }
  return Math.min(4, Math.max(2, value.length));
}

function uniqueTerms(values: string[]): string[] {
  return [...new Set(values.map((value) => value.trim()).filter(Boolean))];
}

export function levenshtein(a: string, b: string): number {
  const previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  const current = new Array<number>(b.length + 1);

  for (let i = 1; i <= a.length; i += 1) {
    current[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(current[j - 1] + 1, previous[j] + 1, previous[j - 1] + cost);
    }
    for (let j = 0; j <= b.length; j += 1) {
      previous[j] = current[j];
    }
  }

  return previous[b.length];
}
