/**
 * explicit_slurs.h — explicit-slur detection for record keys.
 *
 * Ports the reference's hasExplicitSlur (packages/pds/src/handle/
 * explicit-slurs.ts, itself sourced from https://github.com/Blank-Cheque/
 * Slurs), used by prepareCreate/prepareUpdate (packages/pds/src/repo/
 * prepare.ts) to reject a record key containing an explicit slur,
 * independent of general rkey syntax validation.
 */

#ifndef METALBEAR_REPO_EXPLICIT_SLURS_H
#define METALBEAR_REPO_EXPLICIT_SLURS_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * True when `text` -- or `text` with every '.', '-', and '_' removed --
 * matches one of the reference's explicit-slur detection patterns. Matches
 * the reference's own dual test (hasExplicitSlur): a slur hidden behind
 * those separators is still caught.
 *
 * Returns 0 (no match) if `text` is NULL or the pattern set fails to
 * compile (logged; never crashes the caller into treating unrelated input
 * as a slur match).
 */
int metalbear_has_explicit_slur(const char *text);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_REPO_EXPLICIT_SLURS_H */
