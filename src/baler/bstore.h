#ifndef __BSTORE_H_
#define __BSTORE_H_

#include "btkn_types.h"
#include "btypes.h"

/**
 * \defgroup bstore_dev Baler Store Interface for Developers
 * \{
 * \brief Baler store interface.
 *
 * A baler store plugin must implement \c bstore_plugin_s interface.
 */

struct bstore_plugin_s;

typedef struct bstore_s {
	struct bstore_plugin_s *plugin;
	struct bhash_u_s *bhash_u;
	char *path;
} *bstore_t;

typedef enum bstore_iter_type {
	BTKN_ITER,
	BMSG_ITER,
	BPTN_ITER,
	BPTN_TKN_ITER,
	BTKN_HIST_ITER,
	BPTN_HIST_ITER,
	BCOMP_HIST_ITER,
	BPTN_ATTR_ITER,
} bstore_iter_type_t;

typedef struct bstore_iter_s {
	bstore_t bs;
	bstore_iter_type_t type;
} *bstore_iter_t;

typedef bstore_iter_t bmsg_iter_t;
typedef bstore_iter_t btkn_iter_t;
typedef bstore_iter_t bptn_iter_t;
typedef bstore_iter_t bptn_tkn_iter_t;
typedef bstore_iter_t bcomp_hist_iter_t;
typedef bstore_iter_t bptn_hist_iter_t;
typedef bstore_iter_t btkn_hist_iter_t;
typedef bstore_iter_t battr_iter_t;
typedef bstore_iter_t bptn_attr_iter_t;
typedef bstore_iter_t battr_ptn_iter_t;

typedef uint64_t bstore_iter_pos_t;

struct bstore_iter_filter_s {
	struct timeval tv_begin;
	struct timeval tv_end;
	bptn_id_t ptn_id;
	bcomp_id_t comp_id;
	btkn_id_t tkn_id;
	uint64_t tkn_pos;
	uint64_t bin_width;
	const char *attr_type;
	const char *attr_value;
};

typedef struct bstore_iter_filter_s *bstore_iter_filter_t;

/**
 * Return !0 if the current iterator object should be returned
 *
 * The iterator will call this function for each message in the
 * iterator and skip it, i.e. not return it to the caller if the
 * callback function returns a value other than zero.
 *
 * \param ptn_id The pattern id of the candidate message
 * \param ts The unix timestamp of the candidate message
 * \param comp_id The component id of the candidate message
 * \param ctxt The \c ctxt parameter passed to the bstore_first_msg() function
 * \retval 0 The candidate message is a match
 * \retval !0 The candidate message is not a match and should be skipped
 */
typedef int (*bmsg_cmp_fn_t)(bptn_id_t ptn_id, time_t ts,
			     bcomp_id_t comp_id, void *ctxt);

/**
 * \brief bstore plugin interface.
 *
 * A bstore plugin implmentation shall provide functions declared in this
 * structure. The structure ::bstore_plugin_s serves only as a collection of
 * interface functions of a bstore implementation. The plugin shall extend
 * `struct bstore_s` in order to manage the states of the store.
 *
 * An application open a bstore via ::bstore_open() function. The function then
 * dynamically load the plugin library (specified by `const char *plugin`
 * parameter) and call plugin's `get_plugin()` function to retreive the plugin
 * handle. The `bstore->open()` is then called to open the store (with given
 * `const char *path` and other open parameters).
 */
typedef struct bstore_plugin_s {

	/**
	 * \brief Open the store.
	 *
	 * \param plugin The pointer to the plugin structure
	 * \param path The path of the store
	 * \param flags The open flags (ored combination of \c O_CREAT, and \c
	 *              O_RDWR)
	 * \param o_mode The mode if \c flags has \c O_CREAT
	 *
	 * \retval bstore_t A bstore handle
	 */
	bstore_t (*open)(struct bstore_plugin_s *plugin, const char *path,
			 int flags, int o_mode);

	/**
	 * \brief Close the store.
	 *
	 * \note The plugin shall free the resources allocated in \c open()
	 *       here.
	 *
	 * \param bstore_t The store handle obtained \c open()
	 */
	void (*close)(bstore_t bs);

	/**
	 * \brief Add a token into the store.
	 *
	 * If the token is not present in the store, add it. In either
	 * case, return it's tkn_id
	 *
	 * \param bs The bstore handle
	 * \param tkn The token to be inserted
	 *
	 * \retval tkn_id The ID associated with the token \c tkn
	 */
	btkn_id_t (*tkn_add)(bstore_t bs, btkn_t tkn);

	/**
	 * \brief Add a token with an id.
	 *
	 * The token id cannot already exist.
	 *
	 * \param bs The bstore handle
	 * \param tkn The token to be inserted. \c tkn->tkn_id is the ID the
	 *            caller wants to assign to the token.
	 *
	 * \retval 0 If the insertion is a success
	 * \retval errno If the insertion is a failure
	 */
	int (*tkn_add_with_id)(bstore_t bs, btkn_t tkn);

	/**
	 * \brief Find a token by ID.
	 *
	 * \note The caller must call \c btkn_free() to free the token.
	 *
	 * \param bs The bstore handle
	 * \param tkn_id The token ID
	 *
	 * \retval btkn_t A pointer to the token structure if the token exists
	 * \retval NULL If the token does not exist
	 */
	btkn_t (*tkn_find_by_id)(bstore_t bs, btkn_id_t tkn_id);

	/**
	 * \brief Find a token by name (string).
	 *
	 * \param bs The bstore handle
	 * \param name The (string) name of the token
	 * \param name_len The length (excluding '\0') of the token
	 *
	 * \retval btkn_t A pointer to the token structure if the token exists
	 * \retval NULL If the token does not exist
	 */
	btkn_t (*tkn_find_by_name)(bstore_t bs, const char *name, size_t name_len);

	/**
	 * \defgroup bstore_dev_tkn_iter (DEV) Baler Store Token Iterator
	 * \ingroup bstore_dev
	 * \{
	 */

	/**
	 * \brief Returns a current position of the iterator.
	 *
	 * \param iter The iterator handle
	 * \retval ptr The pointer to the structure extending \c
	 *             bstore_iter_pos_s that describes the iterator position
	 * \retval NULL If there is an error, in which case \c errno must be set
	 *              to describe the error
	 */
	bstore_iter_pos_t (*iter_pos_get)(bstore_iter_t iter);

	/**
	 * \brief Set the iterator \c iter position to the given position \c pos.
	 *
	 * \param iter The iterator handle
	 * \param pos The iterator position
	 *
	 * \retval 0 If the operation is a success
	 * \retval errno If there is an error
	 */
	int (*iter_pos_set)(bstore_iter_t iter, bstore_iter_pos_t pos);

	/**
	 * \brief Free the iterator position
	 *
	 * \param iter The iterator handle
	 * \param pos The iterator position
	 *
	 * \retval 0 If the operation is a success
	 * \retval errno If there is an error
	 */
	void (*iter_pos_free)(bstore_iter_t iter, bstore_iter_pos_t pos);

	/**
	 * Create a new token iterator.
	 *
	 * \param bs The bstore handle
	 *
	 * \retval btkn_iter_t The iterator handle
	 * \retval NULL If there is an error, \c errno must also be set to
	 *              describe the error
	 */
	btkn_iter_t (*tkn_iter_new)(bstore_t bs);

	/**
	 * Free the token iterator.
	 *
	 * \param iter The token iterator handle
	 */
	void (*tkn_iter_free)(btkn_iter_t iter);

	/**
	 * \brief The number of items left in the iterator.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval card The number of items left in the iterator.
	 */
	uint64_t (*tkn_iter_card)(btkn_iter_t iter);

	/**
	 * \brief Obtain the current token.
	 *
	 * \note The plugin doesn't know when the caller call \c btkn_free().
	 *
	 * \param iter The iterator handle
	 *
	 * \retval tkn The token object; The caller owns the object and is
	 *             responsible for freeing it (with \c btkn_free())
	 * \retval NULL If there is an error
	 */
	btkn_t (*tkn_iter_obj)(btkn_iter_t iter);

	/**
	 * \brief Set the iterator position to the first token.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*tkn_iter_first)(btkn_iter_t iter);

	/**
	 * \brief Set the iterator position to the next token.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*tkn_iter_next)(btkn_iter_t iter);

	/**
	 * \brief Set the iterator position to the previous token.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*tkn_iter_prev)(btkn_iter_t iter);

	/**
	 * \brief Set the iterator position to the last token.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*tkn_iter_last)(btkn_iter_t iter);

	/**
	 * \}
	 */


	/**
	 * \brief Add the message to the store
	 */
	int (*msg_add)(bstore_t bs, struct timeval *tv, bmsg_t msg);


	/**
	 * \defgroup bstore_dev_msg_iter (DEV) Baler Store Message Iterator
	 * \ingroup bstore_dev
	 * \{
	 *
	 * \brief Message Iterator and Filter.
	 *
	 * The application can use message iterator to obtain messages from
	 * bstore. A message iterator is created by \c msg_iter_new().
	 *
	 * The message iterator position can be set by \c msg_iter_find_fwd(),
	 * \c msg_iter_find_rev(), or \c iter_pos_set(). The current
	 * iterator position can be obtained by \c iter_pos_get().
	 *
	 * The order of the message iteration should be by
	 * \c (time, comp_id, pattern_id), which is the key of the iteration
	 * entries.
	 */

	/**
	 * \brief Create a new message iterator
	 *
	 * \param bs The bstore handle
	 *
	 * \retval iter The new iterator handle
	 * \retval NULL If there is an error
	 */
	bmsg_iter_t (*msg_iter_new)(bstore_t bs);

	/**
	 * \brief Free the iterator
	 *
	 * \param iter The iterator handle
	 */
	void (*msg_iter_free)(bmsg_iter_t iter);

	/**
	 * \brief Get the number of items left in the iterator
	 *
	 * \param iter The iterator handle
	 *
	 * \retval num The number of items left in the iterator
	 */
	uint64_t (*msg_iter_card)(bmsg_iter_t iter);

	/**
	 * \brief Set a filter to the iterator
	 *
	 * By setting a filter, the iterator shall skip the entries not matching
	 * the conditions set by the filter. The filter can be reset using NULL
	 * pointer for \c filter.
	 *
	 * \param iter The iterator handle
	 * \param filter The message iterator filter
	 *
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*msg_iter_filter_set)(bmsg_iter_t iter, bstore_iter_filter_t filter);

	/**
	 * \brief Get the message of the current position.
	 *
	 * \note The plugin doesn't know when the application frees the message
	 *       object with \c bmsg_free().
	 *
	 * \param iter The iterator handle
	 *
	 * \retval bmsg_t The message object
	 * \retval NULL If there is an error, in which case \c errno must be set
	 */
	bmsg_t (*msg_iter_obj)(bmsg_iter_t iter);

	/**
	 * \brief Position the iterator to the first entry of greater/equal key
	 *
	 * \note
	 * - The message key is \c (tv,comp_id,ptn_id).
	 * - The new position must satisfy the iterator filter.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval ENOENT If no such entry is found
	 * \retval errno For other errors
	 */
	int (*msg_iter_find_fwd)(bmsg_iter_t iter, const struct timeval *tv,
				   bcomp_id_t comp_id, bptn_id_t ptn_id);

	/**
	 * \brief Position the iterator to the last entry of less/equal key
	 *
	 * \note
	 * - The message key is \c (tv,comp_id,ptn_id).
	 * - The new position must satisfy the iterator filter.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval ENOENT If no such entry is found
	 * \retval errno For other errors
	 */
	int (*msg_iter_find_rev)(bmsg_iter_t iter, const struct timeval *tv,
				   bcomp_id_t comp_id, bptn_id_t ptn_id);

	/**
	 * \brief Position the iterator to the first entry (subject to the filter)
	 *
	 * \note The new position must satisfy the iterator filter.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval ENOENT If there is not further entries
	 * \retval errno For other errors
	 */
	int (*msg_iter_first)(bmsg_iter_t iter);

	/**
	 * \brief Position the iterator to the next entry (subject to the filter)
	 *
	 * \note The new position must satisfy the iterator filter.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval ENOENT If there is not further entries
	 * \retval errno For other errors
	 */
	int (*msg_iter_next)(bmsg_iter_t iter);

	/**
	 * \brief Position the iterator to the previous entry (subject to the filter)
	 *
	 * \note The new position must satisfy the iterator filter.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval ENOENT If there is not further entries
	 * \retval errno For other errors
	 */
	int (*msg_iter_prev)(bmsg_iter_t iter);

	/**
	 * \brief Position the iterator to the last entry (subject to the filter)
	 *
	 * \note The new position must satisfy the iterator filter.
	 *
	 * \param iter The iterator handle
	 *
	 * \retval 0 If the operation is a success
	 * \retval ENOENT If there is not further entries
	 * \retval errno For other errors
	 */
	int (*msg_iter_last)(bmsg_iter_t iter);

	/**
	 * \}
	 */

	/**
	 *
	 * \defgroup bstore_dev_ptn_iter (DEV) Baler Store Pattern Iterator
	 * \ingroup bstore_dev
	 * \{
	 *
	 * \brief Iterator over Baler Patterns
	 */

	/**
	 * \brief Add the pattern to the store
	 *
	 * If the pattern does not exist, add it into the list and assign a
	 * unique ID to it. If the pattern does exist, update its statistics
	 * (count, first-seen, and last-seen).
	 *
	 * \param bs The bstore handle
	 * \param tv The time value that the pattern occur
	 * \param ptn The pattern to be added.
	 * \retval ptn_id The pattern ID assigned to the pattern
	 */
	bptn_id_t (*ptn_add)(bstore_t bs, struct timeval *tv, bstr_t ptn);

	/**
	 * \brief Find a pattern by ID
	 * \param bs The bstore handle
	 * \param ptn_id The pattern ID
	 * \retval bptn_t The pattern handle. The caller will free the returned
	 *                pattern by calling \c bptn_free().
	 */
	bptn_t (*ptn_find)(bstore_t bs, bptn_id_t ptn_id);

	/**
	 * \brief Find a pattern by `ptn->str`.
	 *
	 * If the pattern is found, populate the attributes of \c ptn with the
	 * information from the store.
	 *
	 * \returns 0 if found
	 * \returns ENOENT if not found
	 */
	int (*ptn_find_by_ptnstr)(bstore_t bs, bptn_t ptn);

	/**
	 * \brief Create a pattern iterator
	 */
	bptn_iter_t (*ptn_iter_new)(bstore_t bs);

	/**
	 * \brief Destroy a pattern iterator
	 */
	void (*ptn_iter_free)(bptn_iter_t i);

	/**
	 * \brief Set the filter
	 */
	int (*ptn_iter_filter_set)(bmsg_iter_t iter,
				   bstore_iter_filter_t filter);

	/**
	 * \brief Returns the number of entires in the iteator
	 */
	uint64_t (*ptn_iter_card)(bptn_iter_t i);

	/**
	 * Return the first pattern
	 */
	int (*ptn_iter_find_fwd)(bptn_iter_t iter, bptn_id_t ptn_id);

	/**
	 * Return the first pattern
	 */
	int (*ptn_iter_find_rev)(bptn_iter_t iter, bptn_id_t ptn_id);


	/**
	 * \brief Return the pattern object.
	 * \note The caller is responsible for freeing the returned pattern (by
	 *       calling \c bptn_free()).
	 */
	bptn_t (*ptn_iter_obj)(bptn_iter_t iter);

	/**
	 * \brief Position the next pattern
	 */
	int (*ptn_iter_next)(bptn_iter_t iter);

	/**
	 * \brief Position the previous pattern
	 */
	int (*ptn_iter_prev)(bptn_iter_t iter);

	/**
	 * \brief Position the first pattern
	 */
	int (*ptn_iter_first)(bptn_iter_t iter);

	/**
	 * \brief Position the last pattern
	 */
	int (*ptn_iter_last)(bptn_iter_t iter);

	/**
	 * \}
	 */

	/**
	 *
	 * \defgroup bstore_dev_ptn_tkn_iter (DEV) Baler Store Pattern-Token Iterator
	 * \ingroup bstore_dev
	 * \{
	 *
	 * \brief Iterator over tokens in a pattern.
	 */

	/**
	 * \brief Create a new iterator
	 */
	bptn_tkn_iter_t (*ptn_tkn_iter_new)(bstore_t bs);

	/**
	 * \brief Free the iterator and resources associated with it
	 */
	void (*ptn_tkn_iter_free)(bptn_tkn_iter_t i);

	/**
	 * \brief Returns the number of elements in the iterator
	 */
	uint64_t (*ptn_tkn_iter_card)(bptn_tkn_iter_t i);

	/**
	 * Return the pattern token of the current position
	 */
	btkn_t (*ptn_tkn_iter_obj)(bptn_tkn_iter_t iter);

	/**
	 * \brief Position the iterator to the first object
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*ptn_tkn_iter_first)(bptn_tkn_iter_t iter);

	/**
	 * \brief Position the iterator to the next object
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*ptn_tkn_iter_next)(bptn_tkn_iter_t iter);

	/**
	 * \brief Position the iterator to the previous object
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*ptn_tkn_iter_prev)(bptn_tkn_iter_t iter);

	/**
	 * \brief Position the iterator to the last object
	 * \retval 0 If the operation is a success
	 * \retval errno If the operation is a failure
	 */
	int (*ptn_tkn_iter_last)(bptn_tkn_iter_t iter);

	/**
	 * \brief Set filter (ptn_id, tkn_pos) for the iterator.
	 * \note
	 * Only \c filter->ptn_id and \c filter->tkn_pos are used in this
	 * function. The rest of the parameters are ignored.
	 */
	int (*ptn_tkn_iter_filter_set)(bptn_tkn_iter_t iter,
				       bstore_iter_filter_t filter);
	/**
	 * \}
	 */

	/**
	 * Return the type id for a token type name
	 */
	btkn_type_t (*tkn_type_get)(bstore_t bs, const char *name, size_t name_len);

	/**
	 * \brief Maintain the token histograms
	 *
	 * This function is called repeatedly over each token in the message
	 * balerd is processing. The purpose is to inform bstore about token
	 * occurrences (in the time bin [sec, sec+binwidth)). The plugin shall
	 * update or record the statistics asscordingly.
	 *
	 * \param bs bstore handle
	 * \param sec The start time (seconds since EPOCH) of the time bin
	 * \param bin_width The width (seconds) of the time bin
	 * \param tkn_id The Token ID that occurred in the time bin
	 */
	int (*tkn_hist_update)(bstore_t bs, time_t sec, time_t bin_width,
			       btkn_id_t tkn_id);

	/**
	 * \defgroup bstore_dev_tkn_hist_iter (DEV) Baler Store Token Histogram Iterator
	 * \{
	 * \brief Token Histogram Iterator Routines
	 */

	/**
	 * \brief Create a new token histogram iterator
	 */
	btkn_hist_iter_t (*tkn_hist_iter_new)(bstore_t bs);

	/**
	 * \brief Delete the token histogram iterator
	 */
	void (*tkn_hist_iter_free)(btkn_hist_iter_t iter);

	/**
	 * \brief Set the filter
	 */
	int (*tkn_hist_iter_filter_set)(btkn_hist_iter_t iter,
					bstore_iter_filter_t filter);

	/**
	 * \brief Find the first entry \c x, s.t. \c (key{tkn_h} <= key{x})
	 * \param iter The iterator handle
	 * \param[in] tkn_h Histogram entry `find` parameter
	 */
	int (*tkn_hist_iter_find_fwd)(btkn_hist_iter_t iter, btkn_hist_t tkn_h);

	/**
	 * \brief Find the last entry \c x, s.t. \c (key{x} <= key{tkn_h})
	 * \param iter The iterator handle
	 * \param[in] tkn_h Histogram entry `find` parameter
	 */
	int (*tkn_hist_iter_find_rev)(btkn_hist_iter_t iter, btkn_hist_t tkn_h);

	/**
	 * \brief Retreive the object of the current position
	 * \param[out] tkn_h The pointer to the memory for the output
	 * \retval NULL if the current position is invalid
	 * \retval tkn_h if the current position is valid
	 */
	btkn_hist_t (*tkn_hist_iter_obj)(btkn_hist_iter_t iter,
		     btkn_hist_t tkn_h);

	/**
	 * \brief Position the iterator to the first entry
	 * \retval 0 if success
	 * \retval errno if error
	 */
	int (*tkn_hist_iter_first)(btkn_hist_iter_t iter);

	/**
	 * \brief Position the iterator to the next entry
	 * \retval 0 if success
	 * \retval errno if error
	 */
	int (*tkn_hist_iter_next)(btkn_hist_iter_t iter);

	/**
	 * \brief Position the iterator to the prev entry
	 * \retval 0 if success
	 * \retval errno if error
	 */
	int (*tkn_hist_iter_prev)(btkn_hist_iter_t iter);

	/**
	 * \brief Position the iterator to the last entry
	 * \retval 0 if success
	 * \retval errno if error
	 */
	int (*tkn_hist_iter_last)(btkn_hist_iter_t iter);

	/**
	 * \}
	 */

	/**
	 * Maintain the pattern histograms
	 */
	int (*ptn_hist_update)(bstore_t bs,
			       bptn_id_t ptn_id, bcomp_id_t comp_id,
			       time_t secs, time_t bin_width);

	/**
	 * Record which tokens appeared at which position in the pattern
	 */
	int (*ptn_tkn_add)(bstore_t bs,
			   bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);

	btkn_t (*ptn_tkn_find)(bstore_t bs,
			       bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);

	/**
	 * \defgroup bstore_dev_ptn_hist_iter (DEV) Baler Store Pattern Histogram Iterator
	 * \{
	 * \brief Pattern Histogram Iterator Routines
	 */
	bptn_hist_iter_t (*ptn_hist_iter_new)(bstore_t bs);
	void (*ptn_hist_iter_free)(bptn_hist_iter_t iter);
	bptn_hist_t (*ptn_hist_iter_obj)(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

	/**
	 * \brief Set the filter
	 */
	int (*ptn_hist_iter_filter_set)(btkn_hist_iter_t iter,
					bstore_iter_filter_t filter);
	int (*ptn_hist_iter_find_fwd)(bptn_hist_iter_t iter, bptn_hist_t ptn_h);
	int (*ptn_hist_iter_find_rev)(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

	int (*ptn_hist_iter_first)(bptn_hist_iter_t iter);
	int (*ptn_hist_iter_next)(bptn_hist_iter_t iter);
	int (*ptn_hist_iter_prev)(bptn_hist_iter_t iter);
	int (*ptn_hist_iter_last)(bptn_hist_iter_t iter);

	/**
	 * \}
	 */

	/**
	 * \defgroup bstore_dev_comp_hist_iter (DEV) Baler Store Component Histogram Iterator
	 * \{
	 * \brief Component Histogram Iterator Routines
	 */
	bcomp_hist_iter_t (*comp_hist_iter_new)(bstore_t bs);
	void (*comp_hist_iter_free)(bcomp_hist_iter_t iter);

	int (*comp_hist_iter_filter_set)(btkn_hist_iter_t iter,
					 bstore_iter_filter_t filter);
	bcomp_hist_t (*comp_hist_iter_obj)(bcomp_hist_iter_t iter,
					   bcomp_hist_t comp_h);

	int (*comp_hist_iter_find_fwd)(bcomp_hist_iter_t iter,
				       bcomp_hist_t comp_h);
	int (*comp_hist_iter_find_rev)(bcomp_hist_iter_t iter,
				       bcomp_hist_t comp_h);

	int (*comp_hist_iter_first)(bcomp_hist_iter_t iter);
	int (*comp_hist_iter_next)(bcomp_hist_iter_t iter);
	int (*comp_hist_iter_prev)(bcomp_hist_iter_t iter);
	int (*comp_hist_iter_last)(bcomp_hist_iter_t iter);

	/**
	 * \}
	 */

	/**
	 * \defgroup bstore_dev_ptn_attr (DEV) Baler Store Pattern Attribute
	 * \{
	 */
	int (*attr_new)(bstore_t bs, const char *attr_type);
	int (*attr_find)(bstore_t bs, const char *attr_type);
	/* Set attr-value to a pattern. If attr does not exist for the pattern,
	 * add it automatically. If it does exist, just re-set the value. */
	int (*ptn_attr_value_set)(bstore_t bs, bptn_id_t ptn_id,
				  const char *attr_type,
				  const char *attr_value);
	/* For multi-value attribute (e.g. tags) */
	int (*ptn_attr_value_add)(bstore_t bs, bptn_id_t ptn_id,
				  const char *attr_type,
				  const char *attr_value);
	/* For multi-value attribute (e.g. tags) */
	int (*ptn_attr_value_rm)(bstore_t bs, bptn_id_t ptn_id,
				 const char *attr_type,
				 const char *attr_value);
	int (*ptn_attr_unset)(bstore_t bs, bptn_id_t ptn_id,
				  const char *attr_type);
	char *(*ptn_attr_get)(bstore_t bs, bptn_id_t ptn_id,
			      const char *attr_type);

	/* attr iterator */
	battr_iter_t (*attr_iter_new)(bstore_t bs);
	void (*attr_iter_free)(battr_iter_t iter);
	int (*attr_iter_filter_set)(battr_iter_t iter,
					 bstore_iter_filter_t filter);
	char *(*attr_iter_obj)(battr_iter_t iter);
	int (*attr_iter_find)(battr_iter_t iter, const char *attr_type);
	int (*attr_iter_first)(battr_iter_t iter);
	int (*attr_iter_next)(battr_iter_t iter);
	int (*attr_iter_prev)(battr_iter_t iter);
	int (*attr_iter_last)(battr_iter_t iter);

	/* ptn-attr iterator */
	bptn_attr_iter_t (*ptn_attr_iter_new)(bstore_t bs);
	void (*ptn_attr_iter_free)(bptn_attr_iter_t iter);
	int (*ptn_attr_iter_filter_set)(bptn_attr_iter_t iter,
					 bstore_iter_filter_t filter);
	bptn_attr_t (*ptn_attr_iter_obj)(bptn_attr_iter_t iter);
	int (*ptn_attr_iter_find_fwd)(bptn_attr_iter_t iter,
				      bptn_id_t ptn_id,
				      const char *attr_type,
				      const char *attr_value);
	int (*ptn_attr_iter_find_rev)(bptn_attr_iter_t iter,
				      bptn_id_t ptn_id,
				      const char *attr_type,
				      const char *attr_value);
	int (*ptn_attr_iter_first)(bptn_attr_iter_t iter);
	int (*ptn_attr_iter_next)(bptn_attr_iter_t iter);
	int (*ptn_attr_iter_prev)(bptn_attr_iter_t iter);
	int (*ptn_attr_iter_last)(bptn_attr_iter_t iter);

	/**
	 * \}
	 */
} *bstore_plugin_t;

/**
 * \}
 */


/**
 * \defgroup bstore Baler Store Interface for Application
 * \{
 */
typedef bstore_plugin_t (*bstore_init_fn_t)(void);
bstore_t bstore_open(const char *plugin, const char *path, int flags, ...);
void bstore_close(bstore_t bs);
btkn_type_t bstore_tkn_get_type(bstore_t bs, const char *name, size_t name_len);
btkn_id_t bstore_tkn_add(bstore_t bs, btkn_t tkn);
int bstore_tkn_add_with_id(bstore_t bs, btkn_t tkn);
btkn_type_t bstore_tkn_type_get(bstore_t bs, const char *name, size_t len);

btkn_t bstore_tkn_find_by_id(bstore_t bs, btkn_id_t tkn_id);
static inline const char *bstore_tkn_attr_type_str(bstore_t bs, btkn_type_t t)
{
	const char *str = btkn_attr_type_str(t);
	if (!str && t <= BTKN_TYPE_LAST) {
		btkn_t tkn = bstore_tkn_find_by_id(bs, t);
		if (tkn) {
			str = tkn->tkn_str->cstr;
			btkn_free(tkn);
		}
	}
	return str;
}
btkn_t bstore_tkn_find_by_name(bstore_t bs, const char *name, size_t name_len);
btkn_iter_t bstore_tkn_iter_new(bstore_t bs);
void bstore_tkn_iter_free(btkn_iter_t i);
uint64_t bstore_tkn_iter_card(btkn_iter_t i);
btkn_t bstore_tkn_iter_obj(btkn_iter_t iter);
int bstore_tkn_iter_first(btkn_iter_t iter);
int bstore_tkn_iter_next(btkn_iter_t iter);
int bstore_tkn_iter_prev(btkn_iter_t iter);
int bstore_tkn_iter_last(btkn_iter_t iter);

int bstore_msg_add(bstore_t bs, struct timeval *tv, bmsg_t msg);
bmsg_iter_t bstore_msg_iter_new(bstore_t bs);
void bstore_msg_iter_free(bmsg_iter_t i);
uint64_t bstore_msg_iter_card(bmsg_iter_t i);
int bstore_msg_iter_find_fwd(bmsg_iter_t iter, const struct timeval *tv,
			     bcomp_id_t comp_id, bptn_id_t ptn_id);
int bstore_msg_iter_find_rev(bmsg_iter_t iter, const struct timeval *tv,
			     bcomp_id_t comp_id, bptn_id_t ptn_id);
bmsg_t bstore_msg_iter_obj(bmsg_iter_t i);
int bstore_msg_iter_first(bmsg_iter_t i);
int bstore_msg_iter_next(bmsg_iter_t i);
int bstore_msg_iter_prev(bmsg_iter_t i);
int bstore_msg_iter_last(bmsg_iter_t i);
int bstore_msg_iter_filter_set(bmsg_iter_t iter, bstore_iter_filter_t filter);

bptn_id_t bstore_ptn_add(bstore_t bs, struct timeval *tv, bstr_t ptn);
bptn_t bstore_ptn_find(bstore_t bs, bptn_id_t ptn_id);
int bstore_ptn_find_by_ptnstr(bstore_t bs, bptn_t ptn);
bptn_iter_t bstore_ptn_iter_new(bstore_t bs);
void bstore_ptn_iter_free(bptn_iter_t iter);
int bstore_ptn_iter_filter_set(bptn_iter_t iter, bstore_iter_filter_t filter);
uint64_t bstore_ptn_iter_card(bptn_iter_t i);
int bstore_ptn_iter_find_fwd(bptn_iter_t iter, bptn_id_t ptn_id);
int bstore_ptn_iter_find_rev(bptn_iter_t iter, bptn_id_t ptn_id);
bptn_t bstore_ptn_iter_obj(bptn_iter_t iter);
int bstore_ptn_iter_next(bptn_iter_t iter);
int bstore_ptn_iter_prev(bptn_iter_t iter);
int bstore_ptn_iter_first(bptn_iter_t iter);
int bstore_ptn_iter_last(bptn_iter_t iter);

bptn_tkn_iter_t bstore_ptn_tkn_iter_new(bstore_t bs);
void bstore_ptn_tkn_iter_free(bptn_tkn_iter_t iter);
uint64_t bstore_ptn_tkn_iter_card(bptn_tkn_iter_t i);
btkn_t bstore_ptn_tkn_iter_obj(bptn_tkn_iter_t iter);
int bstore_ptn_tkn_iter_first(bptn_tkn_iter_t iter);
int bstore_ptn_tkn_iter_next(bptn_tkn_iter_t iter);
int bstore_ptn_tkn_iter_prev(bptn_tkn_iter_t iter);
int bstore_ptn_tkn_iter_last(bptn_tkn_iter_t iter);
int bstore_ptn_tkn_iter_filter_set(bptn_tkn_iter_t iter,
				   bstore_iter_filter_t filter);

/* Token History */
int bstore_tkn_hist_update(bstore_t bs, time_t secs, time_t bin_width, btkn_id_t tkn_id);
btkn_hist_iter_t bstore_tkn_hist_iter_new(bstore_t bs);
void bstore_tkn_hist_iter_free(btkn_hist_iter_t iter);
int bstore_tkn_hist_iter_filter_set(btkn_hist_iter_t iter,
				    bstore_iter_filter_t filter);
btkn_hist_t bstore_tkn_hist_iter_obj(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
int bstore_tkn_hist_iter_find_fwd(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
int bstore_tkn_hist_iter_find_rev(btkn_hist_iter_t iter, btkn_hist_t tkn_h);
int bstore_tkn_hist_iter_first(btkn_hist_iter_t iter);
int bstore_tkn_hist_iter_next(btkn_hist_iter_t iter);
int bstore_tkn_hist_iter_prev(btkn_hist_iter_t iter);
int bstore_tkn_hist_iter_last(btkn_hist_iter_t iter);

/* Pattern History */
int bstore_ptn_hist_update(bstore_t bs, bptn_id_t ptn_id, bcomp_id_t comp_id,
			   time_t secs, time_t bin_width);
int bstore_ptn_tkn_add(bstore_t bs, bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);
btkn_t bstore_ptn_tkn_find(bstore_t bs,
			   bptn_id_t ptn_id, uint64_t tkn_pos, btkn_id_t tkn_id);
bptn_hist_iter_t bstore_ptn_hist_iter_new(bstore_t bs);
void bstore_ptn_hist_iter_free(bptn_hist_iter_t iter);
bptn_hist_t bstore_ptn_hist_iter_obj(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

int bstore_ptn_hist_iter_filter_set(btkn_hist_iter_t iter,
				    bstore_iter_filter_t filter);
int bstore_ptn_hist_iter_find_fwd(bptn_hist_iter_t iter, bptn_hist_t ptn_h);
int bstore_ptn_hist_iter_find_rev(bptn_hist_iter_t iter, bptn_hist_t ptn_h);

int bstore_ptn_hist_iter_first(bptn_hist_iter_t iter);
int bstore_ptn_hist_iter_next(bptn_hist_iter_t iter);
int bstore_ptn_hist_iter_prev(bptn_hist_iter_t iter);
int bstore_ptn_hist_iter_last(bptn_hist_iter_t iter);

/* Component History */
bcomp_hist_iter_t bstore_comp_hist_iter_new(bstore_t bs);
void bstore_comp_hist_iter_free(bcomp_hist_iter_t iter);
int bstore_comp_hist_iter_find_fwd(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
int bstore_comp_hist_iter_find_rev(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
bcomp_hist_t bstore_comp_hist_iter_obj(bcomp_hist_iter_t iter, bcomp_hist_t comp_h);
int bstore_comp_hist_iter_filter_set(btkn_hist_iter_t iter,
				     bstore_iter_filter_t filter);
int bstore_comp_hist_iter_first(bcomp_hist_iter_t iter);
int bstore_comp_hist_iter_next(bcomp_hist_iter_t iter);
int bstore_comp_hist_iter_prev(bcomp_hist_iter_t iter);
int bstore_comp_hist_iter_last(bcomp_hist_iter_t iter);

/* Iterator position management routines */
bstore_iter_pos_t bstore_iter_pos_get(bstore_iter_t iter);
void bstore_iter_pos_free(bstore_iter_t iter, bstore_iter_pos_t pos_h);
int bstore_iter_pos_set(bstore_iter_t iter, bstore_iter_pos_t pos_h);
char *bstore_pos_to_str(bstore_iter_pos_t pos);
bstore_iter_pos_t bstore_pos_from_str(const char *pos);

/**
 * \defgroup bstore_ptn_attr Baler Store Pattern Attribute
 * \{
 *
 * \brief Baler Store Pattern Attribute Routines
 *
 * In a Baler Store, a pattern can be associated with attributes. The attribute
 * value can be a single string, or a collection of strings. The following is a
 * synopsis how to use it:
 *
 * \code{.py}
 * #!/usr/bin/env python
 * from baler import Bq
 * bs = Bq.Bstore()
 * bs.open("path/to/store")
 *
 * # Create some new attribute types
 * bs.attr_new("TAG") # for pattern tags (multiple tags / pattern)
 * bs.attr_new("NOTE") # a note for a pattern
 *
 * # Set a NOTE attribute
 * bs.ptn_attr_value_set(345, "NOTE", "This is pattern 345.")
 *
 * # Add several tags
 * bs.ptn_attr_value_add(345, "TAG", "example")
 * bs.ptn_attr_value_add(345, "TAG", "bad")
 * bs.ptn_attr_value_add(345, "TAG", "misc")
 *
 * # Getting the value of an attribute of a pattern
 * note = bs.ptn_attr_get(345, "NOTE")
 *
 * # Iterating through multi-value attribute (e.g. TAG) for a pattern
 * itr = Bq.Bptn_attr_iter(bs)
 * itr.set_filter(ptn_id=345, attr_type="TAG")
 * for attr_obj in itr:
 *     print attr_obj.attr_value()
 *     # .ptn_id() for ptn_id, and .attr_type() for attr_type()
 *     # .as_tuple() to get (ptn_id, attr_type, attr_value) tuple
 *
 * # Iterating through all attribute-value of a pattern
 * itr = Bq.Bptn_attr_iter(bs)
 * itr.set_filter(ptn_id=345)
 * for attr_obj in itr:
 *     print (attr_obj.attr_type(), attr_obj.attr_value())
 *
 * # Iterating through all ptn_id-attribute-value
 * itr = Bq.Bptn_attr_iter(bs)
 * for attr_obj in itr:
 *     print attr_obj.as_tuple()
 *
 * # Get all ptn_id's that has a certain value of an attribute (e.g. TAG)
 * itr = Bq.Bptn_attr_iter(bs)
 * itr.set_filter(attr_type="TAG", attr_value="bad")
 * for attr_obj in itr:
 *     print attr_obj.ptn_id()
 *
 * # Get all ptn_id-attr_value of an attribute type
 * itr = Bq.Bptn_attr_iter(bs)
 * itr.set_filter(attr_type="NOTE")
 * # This will give all ptn_id-NOTEs
 * for attr_obj in itr:
 *     print (attr_obj.ptn_id(), attr_obj.attr_value())
 *
 * # Remove an attribute value from a pattern
 * bs.ptn_attr_value_rm(345, "TAG", "bad")
 *
 * \endcode
 *
 * \code{.c}
 * bstore_t bs;
 *
 * bstore_attr_new(bs, "TAG");
 * bstore_attr_new(bs, "NOTE");
 *
 * // Set a NOTE attribute
 * bstore_ptn_attr_value_set(bs, 345, "NOTE", "This is pattern 345.");
 *
 * // Add several tags
 * bstore_ptn_attr_value_add(bs, 345, "TAG", "example");
 * bstore_ptn_attr_value_add(bs, 345, "TAG", "bad");
 * bstore_ptn_attr_value_add(bs, 345, "TAG", "misc");
 *
 * // Getting the value of an attribute of a pattern
 * char *note = bstore_ptn_attr_get(bs, 345, "NOTE");
 * printf("%s", note);
 * free(note);
 *
 * bptn_attr_t ao;
 *
 * // Iterating through multi-value attribute (e.g. TAG) for a pattern
 * bptn_attr_iter_t itr = bstore_ptn_attr_iter_new(bs);
 * struct bstore_iter_filter_s filter = {.ptn_id=345, .attr_type="TAG"};
 * bstore_ptn_attr_iter_filter_set(itr, &filter);
 * for (rc = bstore_ptn_attr_iter_first();
 *                             rc;
 *                             rc = bstore_ptn_attr_iter_next()) {
 *         ao = bstore_ptn_attr_iter_obj();
 *         printf("%s\n", ao->attr_value);
 *         // ao has ptn_id, attr_type and attr_value members
 *         bptn_attr_free(ao);
 * }
 *
 * // Iterating through all attribute-value of a pattern
 * //   Do the same as above, just change the filter
 * bptn_attr_iter_t itr = bstore_ptn_attr_iter_new(bs);
 * struct bstore_iter_filter_s filter = {.ptn_id=345};
 * bstore_ptn_attr_iter_filter_set(itr, &filter);
 * ...
 *
 * // Iterating through all ptn_id-attribute-value
 * //   Do the same as above, just apply no filter
 * bptn_attr_iter_t itr = bstore_ptn_attr_iter_new(bs);
 * for ...
 *
 * // Get all ptn_id's that has a certain value of an attribute (e.g. TAG)
 * //   Do the same as above with different filter
 * bptn_attr_iter_t itr = bstore_ptn_attr_iter_new(bs);
 * struct bstore_iter_filter_s filter = {.attr_type="TAG", .attr_value"bad"};
 * bstore_ptn_attr_iter_filter_set(itr, &filter);
 * ...
 *
 * // Get all ptn_id-attr_value of an attribute type
 * //   Do the same as above with different filter
 * bptn_attr_iter_t itr = bstore_ptn_attr_iter_new(bs);
 * struct bstore_iter_filter_s filter = {.attr_type="NOTE"};
 * bstore_ptn_attr_iter_filter_set(itr, &filter);
 * // This will give all ptn_id-NOTEs
 * ...
 *
 * // Remove an attribute value from a pattern
 * bstore_ptn_attr_value_rm(bs, 345, "TAG", "bad");
 *
 * \endcode
 */

/**
 * \brief Create a new attribute type
 * \retval 0 if success
 * \retval errno if failed
 */
int bstore_attr_new(bstore_t bs, const char *attr_type);

/**
 * \brief Find the attribute type in the store
 * \retval 0 if it is found
 * \retval ENOENT if it is not found
 */
int bstore_attr_find(bstore_t bs, const char *attr_type);

/**
 * \brief Set attribute-value to a pattern.
 *
 * If the pattern does not have the attribute, automatically add it to
 * the pattern. If the pattern have had the attribute, re-set its value.
 *
 * \retval 0 if success
 * \retval errno if failed
 */
int bstore_ptn_attr_value_set(bstore_t bs, bptn_id_t ptn_id,
		const char *attr_type, const char *attr_value);

/**
 * \brief Add a value to the pattern's attribute (multi-value, e.g. tag)
 */
int bstore_ptn_attr_value_add(bstore_t bs, bptn_id_t ptn_id,
		const char *attr_type, const char *attr_value);

/**
 * \brief Remove a value to the pattern's attribute (multi-value, e.g. tag)
 */
int bstore_ptn_attr_value_rm(bstore_t bs, bptn_id_t ptn_id,
		const char *attr_type, const char *attr_value);

/**
 * \brief Unset the pattern attribute
 *
 * For both multi-value and single-value, calling this function will
 * delete the attribute from the pattern.
 */
int bstore_ptn_attr_unset(bstore_t bs, bptn_id_t ptn_id,
		const char *attr_type);

/**
 * \brief Get a value from an attribute type of a pattern
 * \note The caller must free the returned string.
 * \note In the case of multi-value attribute type, the first value is returned.
 */
char *bstore_ptn_attr_get(bstore_t bs, bptn_id_t ptn_id, const char *attr_type);

bptn_attr_iter_t bstore_ptn_attr_iter_new(bstore_t bs);
void bstore_ptn_attr_iter_free(bptn_attr_iter_t iter);
int bstore_ptn_attr_iter_filter_set(bptn_attr_iter_t iter,
				 bstore_iter_filter_t filter);
bptn_attr_t bstore_ptn_attr_iter_obj(bptn_attr_iter_t iter);
int bstore_ptn_attr_iter_find_fwd(bptn_attr_iter_t iter,
			      bptn_id_t ptn_id,
			      const char *attr_type,
			      const char *attr_value);
int bstore_ptn_attr_iter_find_rev(bptn_attr_iter_t iter,
			      bptn_id_t ptn_id,
			      const char *attr_type,
			      const char *attr_value);
int bstore_ptn_attr_iter_first(bptn_attr_iter_t iter);
int bstore_ptn_attr_iter_next(bptn_attr_iter_t iter);
int bstore_ptn_attr_iter_prev(bptn_attr_iter_t iter);
int bstore_ptn_attr_iter_last(bptn_attr_iter_t iter);
/**
 * \}
 */

/**
 * \}
 */

#endif
