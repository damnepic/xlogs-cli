// COMPRESSION, MEASURED (XL-098). What the deployment actually served, summarised from responses
// the scan already fetched. Pure: the caller supplies the rows, so this can be tested directly
// including the partial cases the live path rarely produces.
//
// INVENTORY, not a finding. An uncompressed response is a transfer cost, not a vulnerability. This
// carries no severity, no score, and cannot move a verdict.
//
// WHY THE ENCODING ARRIVES AS ITS OWN FIELD. lib/safe-fetch.mjs decodes the body and then deletes
// the content-encoding header, which is correct: leaving it would tell a consumer to decode bytes
// that are no longer encoded. So the negotiated encoding and the raw wire byte count are carried
// out as properties instead, and this module reads those.
//
// WHAT IS DELIBERATELY ABSENT. The HTTP/2 half of the original idea. The negotiated protocol
// version is not exposed by the request layer we use, and reporting it from a guess would be the
// kind of manufactured number the product refuses. Absent beats invented.

const MAX_LISTED = 10;

/**
 * @param {Array<{url:string, encoding:string|null, bytes:number, transferBytes:number|null}>} rows
 * @returns {object} inventory: no severity, no score
 */
export function compressionSummary(rows) {
  const list = Array.isArray(rows) ? rows.filter((r) => r && typeof r.url === "string") : [];
  if (!list.length) return { status: "inconclusive", reason: "No first-party responses were read, so compression was not measured." };

  const compressed = list.filter((r) => !!r.encoding);
  const uncompressed = list.filter((r) => !r.encoding);

  // A total is reported ONLY when every row supplied one. Summing the rows that happen to have a
  // wire count would produce a smaller number that looks like a complete measurement, which is the
  // same manufactured-confidence failure as a truncated body reported as clean.
  const allHaveTransfer = list.every((r) => Number.isFinite(r.transferBytes));

  return {
    status: "found",
    total: list.length,
    compressed: compressed.length,
    encodings: [...new Set(compressed.map((r) => String(r.encoding).toLowerCase()))].sort(),
    uncompressedUrls: uncompressed.map((r) => r.url).slice(0, MAX_LISTED),
    uncompressedBytes: uncompressed.reduce((n, r) => n + (r.bytes || 0), 0),
    transferBytes: allHaveTransfer ? list.reduce((n, r) => n + r.transferBytes, 0) : null,
    decodedBytes: list.reduce((n, r) => n + (r.bytes || 0), 0),
  };
}
