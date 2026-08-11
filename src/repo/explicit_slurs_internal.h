/**
 * explicit_slurs_internal.h — pattern data shared between the generated
 * pattern table (explicit_slurs_patterns.c) and the matcher
 * (explicit_slurs.c). Not part of the public API; see
 * include/metalbear/repo/explicit_slurs.h for that.
 */

#ifndef METALBEAR_EXPLICIT_SLURS_INTERNAL_H
#define METALBEAR_EXPLICIT_SLURS_INTERNAL_H

#include <stddef.h>

extern const char *const metalbear_explicit_slur_patterns[];
extern const size_t metalbear_explicit_slur_pattern_count;

#endif /* METALBEAR_EXPLICIT_SLURS_INTERNAL_H */
