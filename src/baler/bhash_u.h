/**
 * \file bhash_u.h
 * \author Narate Taerat (narate at ogc dot us)
 *
 * \brief bhash_u is a hash table service with uncontrolled key assignment.
 *
 * The application doesn't have a control of key assignment in this hashing
 * service. The application will get the key by inserting a value into the hash
 * table (see \c bhash_u_inert()). The value doesn't have to be unique. The
 * application can call \c bhash_u_get() to retrieve the associated value. To
 * remove the entry from the hash, call \c bhash_u_delete()
 *
 */
#ifndef __BHASH_U_H
#define __BHASH_U_H

#include <stdint.h>

typedef uint64_t bhash_u_key_t;
typedef uint64_t bhash_u_value_t;

typedef struct bhash_u_s *bhash_u_t;

bhash_u_t bhash_u_new(int htbl_size);
void bhash_u_free(bhash_u_t h);

int bhash_u_insert(bhash_u_t h, bhash_u_value_t value, bhash_u_key_t *key_out);
int bhash_u_remove(bhash_u_t h, bhash_u_key_t k);
int bhash_u_remove2(bhash_u_t h, bhash_u_key_t k, bhash_u_value_t *value_out);
int bhash_u_get(bhash_u_t h, bhash_u_key_t key, bhash_u_value_t *value_out);
int bhash_u_resize(bhash_u_t h, int new_htbl_size);
#endif
