/*
 * ciphra.h — C ABI for the Ciphra engine.
 *
 * The engine (SQL, encryption, key derivation, query planning) runs in
 * the calling process; for remote databases it speaks Ciphra's sealed
 * protocol to a blind `ciphra-server`. Keys and plaintext never leave
 * this side. Every language driver in ../../drivers binds to this ABI.
 *
 * Memory & threading contract:
 *   - Strings passed in are NUL-terminated UTF-8.
 *   - Strings returned by the library are heap-allocated here and MUST
 *     be released with ciphra_string_free() — not the caller's free().
 *   - Fallible calls return NULL and, when out_err != NULL, set *out_err
 *     to a freshly allocated message (also freed with ciphra_string_free).
 *     On success *out_err is set to NULL.
 *   - A CiphraDb* from ciphra_open*() is released with ciphra_close().
 *     Handles are not synchronized; use one from one thread at a time.
 *   - Panics never cross the boundary; they surface as errors.
 */
#ifndef CIPHRA_H
#define CIPHRA_H

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque database handle. */
typedef struct CiphraDb CiphraDb;

/* Library version string; static, do not free. */
const char *ciphra_version(void);

/* Open (or create) a local database in data_dir, sealed under passphrase.
 * Returns NULL on error with *out_err set. */
CiphraDb *ciphra_open(const char *data_dir, const char *passphrase,
                      char **out_err);

/* Connect to a ciphra-server at addr and open the database it stores.
 * server_key_hex pins the server's static transport key (64 hex chars);
 * pass NULL to trust on first use. Returns NULL on error with *out_err. */
CiphraDb *ciphra_open_remote(const char *addr, const char *passphrase,
                             const char *server_key_hex, char **out_err);

/* Execute one or more ';'-separated statements. On success returns a
 * heap-allocated JSON array of per-statement results (free with
 * ciphra_string_free); on error returns NULL with *out_err set. */
char *ciphra_execute(CiphraDb *db, const char *sql, char **out_err);

/* Close and free a database handle. NULL is a no-op. */
void ciphra_close(CiphraDb *db);

/* Free a string returned by this library. NULL is a no-op. */
void ciphra_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* CIPHRA_H */
