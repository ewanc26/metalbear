#ifndef METALBEAR_BACKUP_H
#define METALBEAR_BACKUP_H

#include "wolfram/xrpc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct metalbear_backup metalbear_backup;

wf_status metalbear_backup_create(const char *data_directory,
                                  const char *output_path);
wf_status metalbear_backup_restore(const char *input_path,
                                   const char *data_directory);
wf_status metalbear_backup_verify(const char *backup_path);

#ifdef __cplusplus
}
#endif

#endif
