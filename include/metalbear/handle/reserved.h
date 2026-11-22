/**
 * reserved.h -- reserved-handle labels at signup and handle update.
 *
 * Ports the reference's reservedSubdomains (packages/pds/src/handle/
 * reserved.ts), used by ensureHandleServiceConstraints to reject service
 * labels such as `admin`, `api`, `at` and well-known account names.
 */

#ifndef METALBEAR_HANDLE_RESERVED_H
#define METALBEAR_HANDLE_RESERVED_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * True when the single label immediately before `user_domain` is in the
 * reference's reserved set. Comparison is case-insensitive, matching the
 * reference's handle normalisation.
 *
 * Returns 0 when the handle is not on `user_domain`, has no label before it,
 * or has more than one label there (the reference checks the whole prefix,
 * so a dotted prefix is never a reserved single label). NULL inputs are 0.
 */
int metalbear_handle_is_reserved(const char *handle, const char *user_domain);

#ifdef __cplusplus
}
#endif

#endif /* METALBEAR_HANDLE_RESERVED_H */
