%module Bquery
%include "cpointer.i"
%include "cstring.i"
%include "carrays.i"
%include "stdint.i"
%include "exception.i"
%{
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/queue.h>
#include <sos/sos.h>
#include "baler/bstore.h"
#pragma GCC diagnostic ignored "-Wignored-qualifiers"

static char *format_timestamp(struct timeval *ptv)
{
	static char time_str[80];
#if 0
	size_t len = sizeof(time_str);
	char *tstr;
	struct tm *ptm;
	size_t sz;
	time_t t = ptv->tv_sec;
	ptm = localtime(&t);
	tstr = time_str;
	sz = strftime(tstr, len, "%FT%H:%M:%S", ptm);
	tstr += sz; len -= sz;
	sz = snprintf(tstr, len, ".%d", ptv->tv_usec);
	tstr += sz; len -= sz;
	sz = strftime(tstr, len, "%z", ptm);
#else
	snprintf(time_str, sizeof(time_str), "%d.%06d", ptv->tv_sec, ptv->tv_usec);
#endif
	return time_str;
}

typedef struct {
	bstore_t store;
} *Bstore_t;

Bstore_t Open(const char *plugin, const char *path)
{
	Bstore_t bs = malloc(sizeof *bs);
	if (bs) {
		bs->store = bstore_open(plugin,	path, O_RDONLY, 0);
		if (!bs->store) {
			free(bs);
			bs = NULL;
		}
	}
	return bs;
}

void Close(Bstore_t bs)
{
	bstore_close(bs->store);
	free(bs);
}

typedef uint64_t Btkn_id_t;
typedef struct Btkn_s {
	btkn_t tkn;
	Btkn_id_t tkn_id;
	uint64_t tkn_count;
	size_t tkn_text_len;
	char *tkn_text;
} *Btkn_t;

static PyObject *__make_tkn(btkn_t tkn)
{
	int rc;
	PyObject *ptkn = PyDict_New();
	if (!ptkn)
		goto err_0;
	rc = PyDict_SetItemString(ptkn, "tkn_text",
				  PyString_FromString(tkn->tkn_str->cstr));
	rc = PyDict_SetItemString(ptkn, "tkn_count",
				  PyInt_FromLong(tkn->tkn_count));
	rc = PyDict_SetItemString(ptkn, "tkn_id",
				  PyInt_FromLong(tkn->tkn_id));
	rc = PyDict_SetItemString(ptkn, "tkn_type_mask",
				  PyInt_FromLong(tkn->tkn_type_mask));
	return ptkn;
 err_0:
	return NULL;
}

PyObject *Tkn_Find_By_Id(Bstore_t bs, Btkn_id_t tkn_id)
{
	btkn_t btkn;
	PyObject *ptkn;
	btkn = bstore_tkn_find_by_id(bs->store, tkn_id);
	if (!btkn)
		return Py_None;
	ptkn = __make_tkn(btkn);
	btkn_free(btkn);
	return (ptkn ? ptkn : Py_None);
}

PyObject *Tkn_Find_By_Name(Bstore_t bs, const char *name, size_t name_len)
{
	btkn_t btkn;
	PyObject *ptkn;
	btkn = bstore_tkn_find_by_name(bs->store, name, name_len);
	if (!btkn)
		return Py_None;
	ptkn = __make_tkn(btkn);
	btkn_free(btkn);
	return (ptkn ? ptkn : Py_None);
}
typedef struct Btkn_iter_s {
	btkn_iter_t iter;
	btkn_type_t tkn_type_id;
} *Btkn_iter_t;

Btkn_iter_t Tkn_Iter_New(Bstore_t bs)
{
	Btkn_iter_t i = NULL;
	btkn_iter_t iter = bstore_tkn_iter_new(bs->store);
	if (!bs)
		SWIG_exception(SWIG_ValueError, "Bstore_t parameter is NULL");
	if (iter) {
		i = calloc(1, sizeof *i);
		if (i) {
			i->iter = iter;
		}
	} else {
		SWIG_exception(SWIG_MemoryError, "Insufficient memory");
	}
 fail:
	return i;
}

void Tkn_Iter_Free(Btkn_iter_t i)
{
	bstore_tkn_iter_free(i->iter);
	free(i);
}

uint64_t Tkn_Iter_Card(Btkn_iter_t i)
{
	return bstore_tkn_iter_card(i->iter);
}

PyObject *Tkn_Iter_First(Btkn_iter_t iter)
{
	btkn_t btkn;
	PyObject *ptkn;
	btkn = bstore_tkn_iter_first(iter->iter);
	if (!btkn)
		return Py_None;
	ptkn = __make_tkn(btkn);
	btkn_free(btkn);
	return (ptkn ? ptkn : Py_None);
}

typedef uint64_t Btkn_type_t;
PyObject *Tkn_Iter_Find_By_Type(Btkn_iter_t iter, Btkn_type_t type_id)
{
	btkn_t btkn;
	PyObject *ptkn;
	btkn = bstore_tkn_iter_first(iter->iter);
	if (!btkn)
		return Py_None;
	iter->tkn_type_id = type_id;
	while (btkn && !btkn_has_type(btkn, iter->tkn_type_id)) {
		btkn_free(btkn);
		btkn = bstore_tkn_iter_next(iter->iter);
	}
	if (!btkn)
		return Py_None;
	ptkn = __make_tkn(btkn);
	btkn_free(btkn);
	return (ptkn ? ptkn : Py_None);
}

PyObject *Tkn_Iter_Pos(Btkn_iter_t iter)
{
	bstore_iter_pos_t pos = bstore_tkn_iter_pos(iter->iter);
	if (!pos)
		return Py_None;
	const char *pos_str = bstore_iter_pos_to_str(iter->iter, pos);
	bstore_iter_pos_free(iter->iter, pos);
	if (!pos_str)
		return Py_None;
	PyObject *py_pos = PyString_FromString(pos_str);
	free((char*)pos_str);
	return (py_pos?py_pos:Py_None);
}

PyObject *Tkn_Iter_Pos_Set(Btkn_iter_t iter, PyObject *py_str)
{
	long rc;
	const char *pos_str = PyString_AsString(py_str);
	bstore_iter_pos_t pos = bstore_iter_pos_from_str(iter->iter, pos_str);
	if (!pos) {
		rc = ENOENT;
		goto out;
	}
	rc = bstore_tkn_iter_pos_set(iter->iter, pos);
 out:
	return PyInt_FromLong(rc);
}

PyObject *Tkn_Iter_Next(Btkn_iter_t iter)
{
	btkn_t btkn;
	PyObject *ptkn;
	btkn = bstore_tkn_iter_next(iter->iter);
	if (!btkn)
		return Py_None;
	while (iter->tkn_type_id && btkn && !btkn_has_type(btkn, iter->tkn_type_id)) {
		btkn_free(btkn);
		btkn = bstore_tkn_iter_next(iter->iter);
	}
	if (!btkn)
		return Py_None;
	ptkn = __make_tkn(btkn);
	btkn_free(btkn);
	return (ptkn ? ptkn : Py_None);
}

typedef uint64_t Bptn_id_t;
typedef uint64_t Bcomp_id_t;
typedef struct Bmsg_iter_t {
	Bstore_t bs;
	Bptn_id_t ptn_id;
	Bcomp_id_t comp_id;
	time_t start;
	time_t end;
	bmsg_iter_t iter;
} *Bmsg_iter_t;

Bmsg_iter_t Msg_Iter_New(Bstore_t bs)
{
	Bmsg_iter_t i = NULL;
	bmsg_iter_t iter = bstore_msg_iter_new(bs->store);
	if (!bs)
		SWIG_exception(SWIG_ValueError, "Bstore_t parameter is NULL");
	if (iter) {
		i = malloc(sizeof *i);
		if (i) {
			i->bs = bs;
			i->iter = iter;
		}
	} else {
		SWIG_exception(SWIG_MemoryError, "Insufficient memory");
	}
 fail:
	return i;
}

void Msg_Iter_Free(Bmsg_iter_t i)
{
	bstore_msg_iter_free(i->iter);
	free(i);
}

uint64_t Msg_Iter_Card(Bmsg_iter_t i)
{
	return bstore_msg_iter_card(i->iter);
}

static PyObject *__make_msg(Bstore_t bs, bmsg_t msg)
{
	int rc;
	Py_ssize_t i;
	PyObject *ptkn;
	PyObject *pmsg;
	PyObject *ptkn_str;
	PyObject *ptkn_list;
	PyObject *ptkn_dict;
	PyObject *ptkn_key;

	pmsg = PyDict_New();
	if (!pmsg)
		goto err_0;
	ptkn_list = PyList_New(msg->argc);
	if (!ptkn_list)
		goto err_1;
	ptkn_dict = PyDict_New();
	if (!ptkn_dict)
		goto err_2;
	rc = PyDict_SetItemString(pmsg, "ptn_id",
				  PyInt_FromLong(msg->ptn_id));
	if (rc)
		goto err_3;
	rc = PyDict_SetItemString(pmsg, "comp_id",
				  PyInt_FromLong(msg->comp_id));
	if (rc)
		goto err_3;
	ptkn = Tkn_Find_By_Id(bs, msg->comp_id);
	rc = PyDict_SetItemString(pmsg, "host", ptkn);
	if (rc)
		goto err_3;
	rc = PyDict_SetItemString
		(pmsg, "timestamp",
		 PyString_FromString(format_timestamp(&msg->timestamp))
		 );
	if (rc)
		goto err_3;
	for (i = 0; i < msg->argc; i++) {
		uint64_t key = msg->argv[i];
		btkn_id_t tkn_id = key >> 8;
		btkn_type_t type_id = key & 0xFF;
		ptkn_key = PyInt_FromLong(tkn_id);
		ptkn = PyDict_GetItem(ptkn_dict, ptkn_key);
		if (!ptkn) {
			ptkn = Tkn_Find_By_Id(bs, tkn_id);
			rc = PyDict_SetItem(ptkn_dict, ptkn_key, ptkn);
			if (rc)
				goto err_3;
		}
		Py_DECREF(ptkn_key);
		PyList_SET_ITEM(ptkn_list, i, ptkn);
	}
	rc = PyDict_SetItemString(pmsg, "tkn_list", ptkn_list);
	if (rc)
		goto err_3;
	PyDict_Clear(ptkn_dict);
	Py_DECREF(ptkn_dict);
	return pmsg;
 err_3:
	PyObject_Del(ptkn_dict);
 err_2:
	PyObject_Del(ptkn_list);
 err_1:
	PyObject_Del(pmsg);
 err_0:
	return Py_None;
}
PyObject *Msg_Iter_Find(Bmsg_iter_t i,
		    Bptn_id_t ptn_id,
		    uint32_t start,
		    Bcomp_id_t comp_id)
{
	PyObject *py_msg = Py_None;
	bmsg_t msg;

	i->ptn_id = ptn_id;
	i->start = start;
	i->comp_id = comp_id;
	msg = bstore_msg_iter_find(i->iter, ptn_id, start, comp_id, NULL, NULL);
	if (msg)
		py_msg = __make_msg(i->bs, msg);
	return py_msg;
}

PyObject *Msg_Iter_Next(Bmsg_iter_t i)
{
	PyObject *py_msg = Py_None;
	bmsg_t msg;

	msg = bstore_msg_iter_next(i->iter);
	if (msg)
		py_msg = __make_msg(i->bs, msg);
	return py_msg;
}

PyObject *Msg_Iter_Prev(Bmsg_iter_t i)
{
	PyObject *py_msg = Py_None;
	bmsg_t msg;

	msg = bstore_msg_iter_prev(i->iter);
	if (msg)
		py_msg = __make_msg(i->bs, msg);
	return py_msg;
}

PyObject *Msg_Iter_First(Bmsg_iter_t i)
{
	PyObject *py_msg = Py_None;
	bmsg_t msg;

	i->ptn_id = 0;
	i->start = 0;
	i->comp_id = 0;
	msg = bstore_msg_iter_first(i->iter);
	if (msg)
		py_msg = __make_msg(i->bs, msg);
	return py_msg;
}

PyObject *Msg_Iter_Last(Bmsg_iter_t i)
{
	PyObject *py_msg = Py_None;
	bmsg_t msg;

	msg = bstore_msg_iter_last(i->iter);
	if (msg)
		py_msg = __make_msg(i->bs, msg);
	return py_msg;
}

typedef struct Bptn_iter_t {
	Bstore_t bs;
	bptn_iter_t iter;
} *Bptn_iter_t;

Bptn_iter_t Ptn_Iter_New(Bstore_t bs)
{
	Bptn_iter_t i = NULL;
	bptn_iter_t iter = bstore_ptn_iter_new(bs->store);
	if (!bs)
		SWIG_exception(SWIG_ValueError, "Bstore_t parameter is NULL");
	if (iter) {
		i = malloc(sizeof *i);
		if (i) {
			i->bs = bs;
			i->iter = iter;
		}
	} else {
		SWIG_exception(SWIG_MemoryError, "Insufficient memory");
	}
 fail:
	return i;
}

void Ptn_Iter_Free(Bptn_iter_t i)
{
	bstore_ptn_iter_free(i->iter);
	free(i);
}

uint64_t Ptn_Iter_Card(Bptn_iter_t i)
{
	return bstore_ptn_iter_card(i->iter);
}

static PyObject *__make_ptn(Bstore_t bs, bptn_t ptn)
{
	char row_str[24];
	int rc;
	Py_ssize_t i;
	PyObject *ptkn;
	PyObject *pptn;
	PyObject *ptkn_str;
	PyObject *ptkn_list;
	PyObject *ptkn_dict;
	PyObject *ptkn_key;

	pptn = PyDict_New();
	if (!pptn)
		goto err_0;
	ptkn_list = PyList_New(ptn->tkn_count);
	if (!ptkn_list)
		goto err_1;
	ptkn_dict = PyDict_New();
	if (!ptkn_dict)
		goto err_2;
	rc = PyDict_SetItemString(pptn, "ptn_id",
				  PyInt_FromLong(ptn->ptn_id));
	if (rc)
		goto err_3;
	snprintf(row_str, sizeof(row_str), "row_%d", ptn->ptn_id);
	rc = PyDict_SetItemString(pptn, "DT_RowId", PyString_FromString(row_str));
	if (rc)
		goto err_3;
	rc = PyDict_SetItemString
		(pptn, "first_seen",
		 PyString_FromString(format_timestamp(&ptn->first_seen))
		 );
	if (rc)
		goto err_3;
	rc = PyDict_SetItemString
		(pptn, "last_seen",
		 PyString_FromString(format_timestamp(&ptn->last_seen))
		 );
	if (rc)
		goto err_3;
	rc = PyDict_SetItemString
		(pptn, "count",
		 PyInt_FromLong(ptn->count)
		 );
	if (rc)
		goto err_3;
	for (i = 0; i < ptn->tkn_count; i++) {
		uint64_t key = ptn->str->u64str[i];
		btkn_id_t tkn_id = key >> 8;
		btkn_type_t type_id = key & 0xFF;
		ptkn_key = PyInt_FromLong(tkn_id);
		ptkn = PyDict_GetItem(ptkn_dict, ptkn_key);
		if (!ptkn) {
			ptkn = Tkn_Find_By_Id(bs, tkn_id);
			rc = PyDict_SetItem(ptkn_dict, ptkn_key, ptkn);
			if (rc)
				goto err_3;
		}
		Py_DECREF(ptkn_key);
		PyList_SET_ITEM(ptkn_list, i, ptkn);
	}
	rc = PyDict_SetItemString(pptn, "tkn_list", ptkn_list);
	if (rc)
		goto err_3;
	PyDict_Clear(ptkn_dict);
	Py_DECREF(ptkn_dict);
	return pptn;
 err_3:
	PyObject_Del(ptkn_dict);
 err_2:
	PyObject_Del(ptkn_list);
 err_1:
	PyObject_Del(pptn);
 err_0:
	return Py_None;
}

PyObject *Ptn_Find(Bstore_t bs, Bptn_id_t ptn_id)
{
	bptn_t ptn = bstore_ptn_find(bs->store, ptn_id);
	if (!ptn)
		return NULL;
	return __make_ptn(bs, ptn);
}

PyObject *Ptn_Iter_Find(Bptn_iter_t iter, uint32_t start)
{
	PyObject *py_ptn = Py_None;
	bptn_t ptn;

	ptn = bstore_ptn_iter_find(iter->iter, start);
	if (ptn)
		py_ptn = __make_ptn(iter->bs, ptn);
	return py_ptn;
}

PyObject *Ptn_Iter_Pos(Bptn_iter_t iter)
{
	bstore_iter_pos_t pos = bstore_ptn_iter_pos(iter->iter);
	if (!pos)
		return Py_None;
	const char *pos_str = bstore_iter_pos_to_str(iter->iter, pos);
	bstore_iter_pos_free(iter->iter, pos);
	if (!pos_str)
		return Py_None;
	PyObject *py_pos = PyString_FromString(pos_str);
	free((char*)pos_str);
	return (py_pos?py_pos:Py_None);
}

PyObject *Ptn_Iter_Pos_Set(Bptn_iter_t iter, PyObject *py_str)
{
	long rc;
	const char *pos_str = PyString_AsString(py_str);
	bstore_iter_pos_t pos = bstore_iter_pos_from_str(iter->iter, pos_str);
	if (!pos) {
		rc = ENOENT;
		goto out;
	}
	rc = bstore_ptn_iter_pos_set(iter->iter, pos);
 out:
	return PyInt_FromLong(rc);
}

PyObject *Ptn_Iter_Next(Bptn_iter_t iter)
{
	PyObject *py_ptn = Py_None;
	bptn_t ptn;

	ptn = bstore_ptn_iter_next(iter->iter);
	if (ptn)
		py_ptn = __make_ptn(iter->bs, ptn);
	return py_ptn;
}

PyObject *Ptn_Iter_Prev(Bptn_iter_t iter)
{
	PyObject *py_ptn = Py_None;
	bptn_t ptn;

	ptn = bstore_ptn_iter_prev(iter->iter);
	if (ptn)
		py_ptn = __make_ptn(iter->bs, ptn);
	return py_ptn;
}

PyObject *Ptn_Iter_First(Bptn_iter_t iter)
{
	PyObject *py_ptn = Py_None;
	bptn_t ptn;

	ptn = bstore_ptn_iter_first(iter->iter);
	if (ptn)
		py_ptn = __make_ptn(iter->bs, ptn);
	return py_ptn;
}

PyObject *Ptn_Iter_Last(Bptn_iter_t iter)
{
	PyObject *py_ptn = Py_None;
	bptn_t ptn;

	ptn = bstore_ptn_iter_last(iter->iter);
	if (ptn)
		py_ptn = __make_ptn(iter->bs, ptn);
	return py_ptn;
}

typedef struct Bptn_tkn_iter_t {
	Bstore_t bs;
	bptn_tkn_iter_t iter;
} *Bptn_tkn_iter_t;

Bptn_tkn_iter_t Ptn_Tkn_Iter_New(Bstore_t bs)
{
	Bptn_tkn_iter_t i = NULL;
	bptn_tkn_iter_t iter = bstore_ptn_tkn_iter_new(bs->store);
	if (!bs)
		SWIG_exception(SWIG_ValueError, "Bstore_t parameter is NULL");
	if (iter) {
		i = malloc(sizeof *i);
		if (i) {
			i->bs = bs;
			i->iter = iter;
		}
	} else {
		SWIG_exception(SWIG_MemoryError, "Insufficient memory");
	}
 fail:
	return i;
}

void Ptn_Tkn_Iter_Free(Bptn_tkn_iter_t i)
{
	bstore_ptn_tkn_iter_free(i->iter);
	free(i);
}

uint64_t Ptn_Tkn_Iter_Card(Bptn_tkn_iter_t i)
{
	return bstore_ptn_tkn_iter_card(i->iter);
}

PyObject *Ptn_Tkn_Iter_Find(Bptn_tkn_iter_t iter, Bptn_id_t ptn_id, uint64_t pos)
{
	PyObject *py_tkn = Py_None;
	btkn_t tkn;

	tkn = bstore_ptn_tkn_iter_find(iter->iter, ptn_id, pos);
	if (tkn)
		py_tkn = __make_tkn(tkn);
	return py_tkn;
}

PyObject *Ptn_Tkn_Iter_Pos(Bptn_tkn_iter_t iter)
{
	bstore_iter_pos_t pos = bstore_ptn_tkn_iter_pos(iter->iter);
	if (!pos)
		return Py_None;
	const char *pos_str = bstore_iter_pos_to_str(iter->iter, pos);
	bstore_iter_pos_free(iter->iter, pos);
	if (!pos_str)
		return Py_None;
	PyObject *py_pos = PyString_FromString(pos_str);
	free((char*)pos_str);
	return (py_pos?py_pos:Py_None);
}

PyObject *Ptn_Tkn_Iter_Pos_Set(Bptn_tkn_iter_t iter, PyObject *py_str)
{
	long rc;
	const char *pos_str = PyString_AsString(py_str);
	bstore_iter_pos_t pos = bstore_iter_pos_from_str(iter->iter, pos_str);
	if (!pos) {
		rc = ENOENT;
		goto out;
	}
	rc = bstore_ptn_tkn_iter_pos_set(iter->iter, pos);
 out:
	return PyInt_FromLong(rc);
}

PyObject *Ptn_Tkn_Iter_Next(Bptn_tkn_iter_t iter)
{
	PyObject *py_tkn = Py_None;
	btkn_t tkn;

	tkn = bstore_ptn_tkn_iter_next(iter->iter);
	if (tkn)
		py_tkn = __make_tkn(tkn);
	return py_tkn;
}

/* Token History */
typedef struct Btkn_hist_iter_t {
	Bstore_t bs;
	btkn_hist_iter_t iter;
} *Btkn_hist_iter_t;

Btkn_hist_iter_t Tkn_Hist_Iter_New(Bstore_t bs)
{
	Btkn_hist_iter_t i = NULL;
	btkn_hist_iter_t iter = bstore_tkn_hist_iter_new(bs->store);
	if (!bs)
		SWIG_exception(SWIG_ValueError, "Bstore_t parameter is NULL");
	if (iter) {
		i = malloc(sizeof *i);
		if (i) {
			i->bs = bs;
			i->iter = iter;
		}
	} else {
		SWIG_exception(SWIG_MemoryError, "Insufficient memory");
	}
 fail:
	return i;
}

void Tkn_Hist_Iter_Free(Btkn_hist_iter_t i)
{
	bstore_tkn_hist_iter_free(i->iter);
	free(i);
}

static PyObject *__make_tkn_hist(btkn_hist_t tkn_h)
{
	int rc;
	PyObject *py_tkn_h = PyDict_New();
	if (!py_tkn_h)
		goto err_0;
	rc = PyDict_SetItemString(py_tkn_h, "tkn_id",
				  PyInt_FromLong(tkn_h->tkn_id));
	rc = PyDict_SetItemString(py_tkn_h, "bin_width",
				  PyInt_FromLong((long)tkn_h->bin_width));
	rc = PyDict_SetItemString(py_tkn_h, "time",
				  PyInt_FromLong((long)tkn_h->time));
	rc = PyDict_SetItemString(py_tkn_h, "tkn_count",
				  PyInt_FromLong(tkn_h->tkn_count));
	return py_tkn_h;
 err_0:
	return Py_None;
}

PyObject *Tkn_Hist_Iter_Find(Btkn_hist_iter_t i, uint64_t tkn_id,
			 uint32_t bin_width, uint32_t time)
{
	struct btkn_hist_s hist, *p;

	hist.tkn_id = tkn_id;
	hist.bin_width = bin_width;
	hist.time = time;

	p = bstore_tkn_hist_iter_find(i->iter, &hist);
	if (!p)
		return Py_None;

	return __make_tkn_hist(p);
}

PyObject *Tkn_Hist_Iter_Pos(Btkn_hist_iter_t iter)
{
	bstore_iter_pos_t pos = bstore_tkn_hist_iter_pos(iter->iter);
	if (!pos)
		return Py_None;
	const char *pos_str = bstore_iter_pos_to_str(iter->iter, pos);
	bstore_iter_pos_free(iter->iter, pos);
	if (!pos_str)
		return Py_None;
	PyObject *py_pos = PyString_FromString(pos_str);
	free((char*)pos_str);
	return (py_pos?py_pos:Py_None);
}

PyObject *Tkn_Hist_Iter_Pos_Set(Btkn_hist_iter_t iter, PyObject *py_str)
{
	long rc;
	const char *pos_str = PyString_AsString(py_str);
	bstore_iter_pos_t pos = bstore_iter_pos_from_str(iter->iter, pos_str);
	if (!pos) {
		rc = ENOENT;
		goto out;
	}
	rc = bstore_tkn_hist_iter_pos_set(iter->iter, pos);
 out:
	return PyInt_FromLong(rc);
}

PyObject *Tkn_Hist_Iter_Next(Btkn_hist_iter_t i)
{
	struct btkn_hist_s hist, *p;
	p = bstore_tkn_hist_iter_next(i->iter, &hist);
	if (!p)
		return Py_None;
	return __make_tkn_hist(p);
}

/* Pattern History */
typedef struct Bptn_hist_iter_t {
	Bstore_t bs;
	bptn_hist_iter_t iter;
} *Bptn_hist_iter_t;

Bptn_hist_iter_t Ptn_Hist_Iter_New(Bstore_t bs)
{
	Bptn_hist_iter_t i = NULL;
	bptn_hist_iter_t iter = bstore_ptn_hist_iter_new(bs->store);
	if (iter) {
		i = calloc(1, sizeof *i);
		if (i) {
			i->bs = bs;
			i->iter = iter;
		}
	} else {
		SWIG_exception(SWIG_MemoryError, "Insufficient memory");
	}
 fail:
	return i;
}

void Ptn_Hist_Iter_Free(Bptn_hist_iter_t i)
{
	bstore_ptn_hist_iter_free(i->iter);
	free(i);
}

static PyObject *__make_ptn_hist(bptn_hist_t ptn_h)
{
	int rc;
	PyObject *py_ptn_h = PyDict_New();
	if (!py_ptn_h)
		goto err_0;
	rc = PyDict_SetItemString(py_ptn_h, "ptn_id",
				  PyInt_FromLong(ptn_h->ptn_id));
	rc = PyDict_SetItemString(py_ptn_h, "bin_width",
				  PyInt_FromLong((long)ptn_h->bin_width));
	rc = PyDict_SetItemString(py_ptn_h, "time",
				  PyInt_FromLong((long)ptn_h->time));
	rc = PyDict_SetItemString(py_ptn_h, "msg_count",
				  PyInt_FromLong(ptn_h->msg_count));
	return py_ptn_h;
 err_0:
	return Py_None;
}

PyObject *Ptn_Hist_Iter_Find(Bptn_hist_iter_t i, uint64_t ptn_id,
			 uint32_t bin_width, uint32_t time)
{
	struct bptn_hist_s hist, *p;

	hist.ptn_id = ptn_id;
	hist.bin_width = bin_width;
	hist.time = time;

	p = bstore_ptn_hist_iter_find(i->iter, &hist);
	if (!p)
		return Py_None;

	return __make_ptn_hist(p);
}

PyObject *Ptn_Hist_Iter_Pos(Bptn_hist_iter_t iter)
{
	bstore_iter_pos_t pos = bstore_ptn_hist_iter_pos(iter->iter);
	if (!pos)
		return Py_None;
	const char *pos_str = bstore_iter_pos_to_str(iter->iter, pos);
	bstore_iter_pos_free(iter->iter, pos);
	if (!pos_str)
		return Py_None;
	PyObject *py_pos = PyString_FromString(pos_str);
	free((char*)pos_str);
	return (py_pos?py_pos:Py_None);
}

PyObject *Ptn_Hist_Iter_Pos_Set(Bptn_hist_iter_t iter, PyObject *py_str)
{
	long rc;
	const char *pos_str = PyString_AsString(py_str);
	bstore_iter_pos_t pos = bstore_iter_pos_from_str(iter->iter, pos_str);
	if (!pos) {
		rc = ENOENT;
		goto out;
	}
	rc = bstore_ptn_hist_iter_pos_set(iter->iter, pos);
 out:
	return PyInt_FromLong(rc);
}

PyObject *Ptn_Hist_Iter_Next(Bptn_hist_iter_t i)
{
	struct bptn_hist_s hist, *p;
	p = bstore_ptn_hist_iter_next(i->iter, &hist);
	if (!p)
		return Py_None;
	return __make_ptn_hist(p);
}

/* Component History */
typedef struct Bcomp_hist_iter_t {
	Bstore_t bs;
	bcomp_hist_iter_t iter;
} *Bcomp_hist_iter_t;

Bcomp_hist_iter_t Comp_Hist_Iter_New(Bstore_t bs)
{
	Bcomp_hist_iter_t i = NULL;
	bcomp_hist_iter_t iter = bstore_comp_hist_iter_new(bs->store);
	if (!bs)
		SWIG_exception(SWIG_ValueError, "Bstore_t parameter is NULL");
	if (iter) {
		i = malloc(sizeof *i);
		if (i) {
			i->bs = bs;
			i->iter = iter;
		}
	} else {
		SWIG_exception(SWIG_MemoryError, "Insufficient memory");
	}
 fail:
	return i;
}

void Comp_Hist_Iter_Free(Bcomp_hist_iter_t i)
{
	bstore_comp_hist_iter_free(i->iter);
	free(i);
}

static PyObject *__make_comp_hist(bcomp_hist_t comp_h)
{
	int rc;
	PyObject *py_comp_h = PyDict_New();
	if (!py_comp_h)
		goto err_0;
	rc = PyDict_SetItemString(py_comp_h, "comp_id",
				  PyInt_FromLong(comp_h->comp_id));
	rc = PyDict_SetItemString(py_comp_h, "bin_width",
				  PyInt_FromLong((long)comp_h->bin_width));
	rc = PyDict_SetItemString(py_comp_h, "time",
				  PyInt_FromLong((long)comp_h->time));
	rc = PyDict_SetItemString(py_comp_h, "ptn_id",
				  PyInt_FromLong(comp_h->ptn_id));
	rc = PyDict_SetItemString(py_comp_h, "msg_count",
				  PyInt_FromLong(comp_h->msg_count));
	return py_comp_h;
 err_0:
	return Py_None;
}

PyObject *Comp_Hist_Iter_Find(Bcomp_hist_iter_t i, uint64_t comp_id,
			      uint32_t bin_width, uint32_t time)
{
	struct bcomp_hist_s hist, *p;

	hist.comp_id = comp_id;
	hist.bin_width = bin_width;
	hist.time = time;

	p = bstore_comp_hist_iter_find(i->iter, &hist);
	if (!p)
		return Py_None;

	return __make_comp_hist(p);
}

PyObject *Comp_Hist_Iter_Pos(Bcomp_hist_iter_t iter)
{
	bstore_iter_pos_t pos = bstore_comp_hist_iter_pos(iter->iter);
	if (!pos)
		return Py_None;
	const char *pos_str = bstore_iter_pos_to_str(iter->iter, pos);
	bstore_iter_pos_free(iter->iter, pos);
	if (!pos_str)
		return Py_None;
	PyObject *py_pos = PyString_FromString(pos_str);
	free((char*)pos_str);
	return (py_pos?py_pos:Py_None);
}

PyObject *Comp_Hist_Iter_Pos_Set(Bcomp_hist_iter_t iter, PyObject *py_str)
{
	long rc;
	const char *pos_str = PyString_AsString(py_str);
	bstore_iter_pos_t pos = bstore_iter_pos_from_str(iter->iter, pos_str);
	if (!pos) {
		rc = ENOENT;
		goto out;
	}
	rc = bstore_comp_hist_iter_pos_set(iter->iter, pos);
 out:
	return PyInt_FromLong(rc);
}

PyObject *Comp_Hist_Iter_Next(Bcomp_hist_iter_t i)
{
	struct bcomp_hist_s hist, *p;
	p = bstore_comp_hist_iter_next(i->iter, &hist);
	if (!p)
		return Py_None;
	return __make_comp_hist(p);
}

PyObject *Ptn_Hist(Bstore_t bs, PyObject * py_id_list, uint32_t bin_width,
		   uint32_t start_time, uint32_t end_time)
{
	PyObject *py_obj;
	PyObject *py_list;
	int rc;
	struct bptn_hist_s *hist, **ptn_h;
	bptn_hist_iter_t *i;
	uint32_t bin_time, next_bin;
	Py_ssize_t id, id_count;
	uint64_t min_count = UINTMAX_MAX;
	uint64_t max_count = 0;

	/* clamp start and end times to a multiple of bin_width */
	start_time = (start_time / bin_width)* bin_width;
	end_time = (end_time / bin_width) * bin_width;

	id_count = PyList_Size(py_id_list);
	if (id_count <= 0)
		goto err_0;

	py_obj = PyDict_New();
	if (!py_obj)
		goto err_0;

	i = calloc(id_count, sizeof(void *));
	if (!i)
		goto err_1;

	for (id = 0; id < id_count; id++) {
		i[id] = bstore_ptn_hist_iter_new(bs->store);
		if (!i[id])
			goto err_2;
	}

	ptn_h = calloc(id_count, sizeof(*ptn_h));
	if (!ptn_h)
		goto err_2;

	hist = calloc(id_count, sizeof(*hist));
	if (!hist)
		goto err_3;

	py_list = PyList_New(0);
	if (!py_list)
		goto err_4;

	int more = 0;
	PyObject *py_row = PyList_New(0);
	rc = PyList_Append(py_row, PyString_FromString("Timestamp"));
	for (id = 0; id < id_count; id++) {
		PyObject *py_id = PyList_GetItem(py_id_list, id);
		hist[id].ptn_id = PyInt_AsLong(py_id);
		hist[id].time = start_time;
		hist[id].bin_width = bin_width;

		rc = PyList_Append(py_row, PyString_FromFormat("%d", hist[id].ptn_id));

		ptn_h[id] = bstore_ptn_hist_iter_find(i[id], &hist[id]);
		if (ptn_h[id])
			more = 1;
	}
	rc = PyList_Append(py_list, py_row);
	if (!rc)
		Py_DECREF(py_row);
	for (bin_time = start_time; more; bin_time = next_bin) {
		/*
		 * For each pattern, check if the iterator entry matches
		 * the current bin, if it does, add it to the bin and
		 * advance to the next entry on that pattern's
		 * iterator
		 */
		if (end_time && (bin_time > end_time))
			break;
		more = 0;
		next_bin = 0xffffffff;
		py_row = NULL;
		for (id = 0; id < id_count; id++) {
			if (!ptn_h[id])
				continue;
			if (hist[id].time > bin_time) {
				if (!end_time || (hist[id].time <= end_time))
					more = 1;
				if (next_bin > hist[id].time)
					next_bin = hist[id].time;
				continue;
			}
			/*
			 * At least one of our series has a value in
			 * this bin, write out the row. We add a
			 * column to the row for the bin timestamp
			 */
			if (!py_row) {
				py_row = PyList_New(0);
				if (!py_row)
					goto err_4;
			}
			more = 1;
		}
		if (!py_row)
			continue;
		/* Format is [ time, count_0, count_1, ...., count_N ] */
		rc = PyList_Append(py_row, PyString_FromFormat("%d", bin_time));
		for (id = 0; id < id_count; id++) {
			long msg_count;
			if (ptn_h[id] && hist[id].time == bin_time) {
				msg_count = ptn_h[id]->msg_count;
				ptn_h[id] = bstore_ptn_hist_iter_next(i[id], &hist[id]);
				if (ptn_h[id] && next_bin > ptn_h[id]->time)
					next_bin = ptn_h[id]->time;
			} else {
				msg_count = 0;
			}
			if (msg_count > max_count)
				max_count = msg_count;
			if (msg_count < min_count)
				min_count = msg_count;
			rc = PyList_Append(py_row, PyInt_FromLong(msg_count));
		}
		rc = PyList_Append(py_list, py_row);
		if (!rc)
			Py_DECREF(py_row);
	}
	rc = PyDict_SetItemString(py_obj, "start_time", PyLong_FromLong(start_time));
	rc = PyDict_SetItemString(py_obj, "end_time", PyLong_FromLong(start_time));
	rc = PyDict_SetItemString(py_obj, "bin_width", PyLong_FromLong(bin_width));
	rc = PyDict_SetItemString(py_obj, "min_count", PyLong_FromLong(min_count));
	rc = PyDict_SetItemString(py_obj, "max_count", PyLong_FromLong(max_count));
	rc = PyDict_SetItemString(py_obj, "histogram", py_list);
	if (!rc)
		Py_DECREF(py_list);
	for (id = 0; id < id_count; id++) {
		if (i[id])
			bstore_ptn_hist_iter_free(i[id]);
	}
	free(i);
	free(ptn_h);
	free(hist);
	return py_obj;
 err_4:
	free(hist);
 err_3:
	free(ptn_h);
 err_2:
	for (id = 0; id < id_count; id++) {
		if (i[id])
			bstore_ptn_hist_iter_free(i[id]);
	}
	free(i);
 err_1:
	PyObject_Del(py_obj);
 err_0:
	return Py_None;
}

/*
  { // hist_dict
    start_time : <timestamp>,
    end_time   : <timestamp>,
    bin_width  : <int>,
    min_count  : <int>,
    max_count  : <int>,
    comp_hist  : [ // comp_list
      { // comp_row
        comp_id : <comp_id>,
	histogram : [ // comp_hist_row
	  [ <timestamp>, <count>, [ <ptn_id>, <ptn_id>, ... ]],	// hist_row
	  [ <timestamp>, <count> ],
	  . . .
	  [ <timestamp>, <count> ]
	]
      },
      . . .
    ]
  }
*/
PyObject *Comp_Hist(Bstore_t bs, PyObject *comp_id_list, PyObject *ptn_id_list,
		    uint32_t bin_width, uint32_t start_time, uint32_t end_time)
{
	PyObject *hist_dict;
	PyObject *comp_list;
	PyObject *ptn_list;
	PyObject *comp_row;
	PyObject *comp_hist_row;
	PyObject *hist_row;
	int rc;
	struct bcomp_hist_s comp_h;
	bcomp_hist_iter_t comp_iter;
	uint32_t bin_time, next_bin;
	Py_ssize_t comp_id, comp_id_count;
	Py_ssize_t ptn_id, ptn_id_count;
	uint64_t *ptn_ids = NULL;
	uint64_t *comp_ids = NULL;
	uint64_t msg_count;
	uint64_t min_count = UINTMAX_MAX;
	uint64_t max_count = 0;
	uint64_t min_comp_id = UINTMAX_MAX;
	uint64_t max_comp_id = 0;
	uint32_t last_time = 0;

	/* clamp start and end times to a multiple of bin_width */
	start_time = (start_time / bin_width)* bin_width;
	end_time = (end_time / bin_width) * bin_width;

	if (comp_id_list != Py_None)
		comp_id_count = PyList_Size(comp_id_list);
	else
		comp_id_count = 0;
	if (comp_id_count < 0)
		goto err_0;

	if (ptn_id_list != Py_None)
		ptn_id_count = PyList_Size(ptn_id_list);
	else
		ptn_id_count = 0;
	if (ptn_id_count < 0)
		goto err_0;

	comp_ids = calloc(comp_id_count, sizeof(*comp_ids));
	if (!comp_ids)
		goto err_0;

	ptn_ids = calloc(ptn_id_count, sizeof(*ptn_ids));
	if (!ptn_ids)
		goto err_1;

	hist_dict = PyDict_New();
	if (!hist_dict)
		goto err_2;

	comp_list = PyList_New(0);
	if (!comp_list)
		goto err_3;

	comp_iter = bstore_comp_hist_iter_new(bs->store);
	if (!comp_iter)
		goto err_4;

	if (comp_id_count) {
		int i;
		for (i = 0; i < comp_id_count; i++) {
			PyObject *py_id = PyList_GetItem(comp_id_list, i);
			comp_ids[i] = PyInt_AsLong(py_id);
		 }
	}

	if (ptn_id_count) {
		int i;
		for (i = 0; i < ptn_id_count; i++) {
			PyObject *py_id = PyList_GetItem(ptn_id_list, i);
			ptn_ids[i] = PyInt_AsLong(py_id);
		 }
	}

	/* Build the table */
	int comp_idx = 0;
	memset(&comp_h, 0, sizeof(comp_h));
	if (comp_id_count)
		comp_h.comp_id = comp_ids[0];
	else
		comp_h.comp_id = 0;
	comp_h.bin_width = bin_width;
	comp_h.time = start_time;
	comp_h.ptn_id = 0;
	bcomp_hist_t h = bstore_comp_hist_iter_find(comp_iter, &comp_h);
	if (!h
	    || (comp_h.bin_width != bin_width)
	    || (end_time && comp_h.time > end_time)
	    )
		goto out_0;

	start_time = bin_time = comp_h.time;
	rc = PyDict_SetItemString(hist_dict, "start_time", PyInt_FromLong(comp_h.time));
	rc = PyDict_SetItemString(hist_dict, "bin_width", PyInt_FromLong(comp_h.bin_width));
	rc = PyDict_SetItemString(hist_dict, "comp_hist", comp_list);

	for (comp_idx = 0; h && (!comp_id_count || comp_idx < comp_id_count); comp_idx++) {

		comp_row = PyDict_New();
		if (!comp_row)
			goto out_0;
		comp_hist_row = PyList_New(0);
		if (!comp_hist_row)
			goto out_0;

		comp_id = comp_h.comp_id;
		btkn_t tkn = bstore_tkn_find_by_id(bs->store, comp_id);
		if (tkn) {
			rc = PyDict_SetItemString(comp_row, "comp_name",
						  PyString_FromString(tkn->tkn_str->cstr));
			free(tkn);
		} else {
			rc = PyDict_SetItemString(comp_row, "comp_name",
						  PyString_FromFormat("%lu", comp_h.comp_id));
		}
		rc = PyDict_SetItemString(comp_row, "comp_id",
					  PyInt_FromLong(comp_h.comp_id));
		rc = PyDict_SetItemString(comp_row, "histogram", comp_hist_row);
		rc = PyList_Append(comp_list, comp_row);

		for (bin_time = start_time;
		     h && (comp_h.comp_id == comp_id) &&
			     ((0 == end_time) || (bin_time <= end_time));
		     bin_time = comp_h.time) {
			msg_count = 0;
			ptn_list = PyList_New(0);
			if (!ptn_list)
				goto out_0;
			while (h &&
			       (comp_h.time == bin_time)
			       && (comp_h.bin_width == bin_width)
			       && (comp_h.comp_id == comp_id))
				{
				/* Sum message counts for matching patterns */
				if (ptn_id_count) {
					int i;
					for (i = 0; i < ptn_id_count; i++) {
						if (ptn_ids[i] == comp_h.ptn_id) {
							PyObject *ptn_ent = PyList_New(0);
							if (!ptn_ent)
								goto out_0;
							PyList_Append(ptn_ent, PyInt_FromLong(comp_h.ptn_id));
							PyList_Append(ptn_ent, PyInt_FromLong(comp_h.msg_count));
							PyList_Append(ptn_list, ptn_ent);
							msg_count += comp_h.msg_count;
							break;
						}
					}
				} else {
					PyObject *ptn_ent = PyList_New(0);
					if (!ptn_ent)
						goto out_0;
					PyList_Append(ptn_ent, PyInt_FromLong(comp_h.ptn_id));
					PyList_Append(ptn_ent, PyInt_FromLong(comp_h.msg_count));
					PyList_Append(ptn_list, ptn_ent);
					msg_count += comp_h.msg_count;
				}
				h = bstore_comp_hist_iter_next(comp_iter, &comp_h);
			}
			if (msg_count) {
				hist_row = PyList_New(0);
				if (!hist_row)
					goto out_0;
				PyList_Append(hist_row, PyInt_FromLong(bin_time));
				PyList_Append(hist_row, PyInt_FromLong(msg_count));
				PyList_Append(hist_row, ptn_list);
				PyList_Append(comp_hist_row, hist_row);
				if (bin_time > last_time)
					last_time = bin_time;
				if (msg_count < min_count)
					min_count = msg_count;
				if (msg_count > max_count)
					max_count = msg_count;
				if (comp_id < min_comp_id)
					min_comp_id = comp_id;
				if (comp_id > max_comp_id)
					max_comp_id = comp_id;
			} else
				Py_DECREF(ptn_list);
		}
	}
 out_0:
	rc = PyDict_SetItemString(hist_dict, "end_time", PyInt_FromLong(last_time));
	rc = PyDict_SetItemString(hist_dict, "min_count", PyInt_FromLong(min_count));
	rc = PyDict_SetItemString(hist_dict, "max_count", PyInt_FromLong(max_count));
	rc = PyDict_SetItemString(hist_dict, "min_comp_id", PyInt_FromLong(min_comp_id));
	rc = PyDict_SetItemString(hist_dict, "max_comp_id", PyInt_FromLong(max_comp_id));
	free(comp_ids);
	free(ptn_ids);
	return hist_dict;
 err_4:
	Py_DECREF(comp_list);
 err_3:
	Py_DECREF(hist_dict);
 err_2:
	free(ptn_ids);
 err_1:
	free(comp_ids);
 err_0:
	return Py_None;
}

/*
  { // hist_dict
    start_time : <timestamp>,
    end_time   : <timestamp>,
    bin_width  : <int>,
    min_count  : <int>,
    max_count  : <int>,
    comp_ptn_hist  : [ // comp_ptn_hist
      [ <comp_id>, <timestamp>, <ptn_id>, <msg_count> ], // comp_ptn_row
      . . .
    ]
  }
*/
static PyObject *make_comp_ptn_row(bcomp_hist_t comp)
{
	PyObject *comp_ptn_row = PyList_New(0);
	PyList_Append(comp_ptn_row, PyInt_FromLong(comp->comp_id));
	PyList_Append(comp_ptn_row, PyInt_FromLong(comp->time));
	PyList_Append(comp_ptn_row, PyInt_FromLong(comp->ptn_id));
	PyList_Append(comp_ptn_row, PyInt_FromLong(comp->msg_count));
	return comp_ptn_row;
}

PyObject *Comp_Ptn_Hist(Bstore_t bs, PyObject *comp_id_list, PyObject *ptn_id_list,
			uint32_t bin_width, uint32_t start_time, uint32_t end_time)
{
	PyObject *hist_dict;
	PyObject *comp_ptn_list;
	PyObject *comp_ptn_row;
	int rc;
	struct bcomp_hist_s comp_h;
	bcomp_hist_iter_t comp_iter;
	uint32_t bin_time, next_bin;
	Py_ssize_t comp_id, comp_id_count;
	Py_ssize_t ptn_id, ptn_id_count;
	uint64_t *ptn_ids = NULL;
	uint64_t *comp_ids = NULL;
	uint64_t msg_count;
	uint64_t min_count = UINTMAX_MAX;
	uint64_t max_count = 0;
	uint32_t last_time = 0;

	/* clamp start and end times to a multiple of bin_width */
	start_time = (start_time / bin_width)* bin_width;
	end_time = (end_time / bin_width) * bin_width;

	if (comp_id_list != Py_None)
		comp_id_count = PyList_Size(comp_id_list);
	else
		comp_id_count = 0;
	if (comp_id_count < 0)
		goto err_0;

	if (ptn_id_list != Py_None)
		ptn_id_count = PyList_Size(ptn_id_list);
	else
		ptn_id_count = 0;
	if (ptn_id_count < 0)
		goto err_0;

	comp_ids = calloc(comp_id_count, sizeof(*comp_ids));
	if (!comp_ids)
		goto err_0;

	ptn_ids = calloc(ptn_id_count, sizeof(*ptn_ids));
	if (!ptn_ids)
		goto err_1;

	hist_dict = PyDict_New();
	if (!hist_dict)
		goto err_2;

	comp_ptn_list = PyList_New(0);
	if (!comp_ptn_list)
		goto err_3;

	comp_iter = bstore_comp_hist_iter_new(bs->store);
	if (!comp_iter)
		goto err_4;

	if (comp_id_count) {
		int i;
		for (i = 0; i < comp_id_count; i++) {
			PyObject *py_id = PyList_GetItem(comp_id_list, i);
			comp_ids[i] = PyInt_AsLong(py_id);
		 }
	}

	if (ptn_id_count) {
		int i;
		for (i = 0; i < ptn_id_count; i++) {
			PyObject *py_id = PyList_GetItem(ptn_id_list, i);
			ptn_ids[i] = PyInt_AsLong(py_id);
		 }
	}

	/* Build the table */
	int comp_idx = 0;
	memset(&comp_h, 0, sizeof(comp_h));
	if (comp_id_count)
		comp_h.comp_id = comp_ids[0];
	else
		comp_h.comp_id = 0;
	comp_h.bin_width = bin_width;
	comp_h.time = start_time;
	comp_h.ptn_id = 0;
	bcomp_hist_t h = bstore_comp_hist_iter_find(comp_iter, &comp_h);
	if (!h
	    || (comp_h.bin_width != bin_width)
	    || (end_time && comp_h.time > end_time)
	    )
		goto out_0;

	start_time = bin_time = comp_h.time;
	rc = PyDict_SetItemString(hist_dict, "start_time", PyInt_FromLong(comp_h.time));
	rc = PyDict_SetItemString(hist_dict, "bin_width", PyInt_FromLong(comp_h.bin_width));
	rc = PyDict_SetItemString(hist_dict, "comp_ptn_hist", comp_ptn_list);

	for (comp_idx = 0; h && (!comp_id_count || comp_idx < comp_id_count); comp_idx++) {

		comp_id = comp_h.comp_id;
		msg_count = 0;

		for (bin_time = start_time;
		     h && (comp_h.comp_id == comp_id) &&
			     ((0 == end_time) || (bin_time <= end_time));
		     bin_time = comp_h.time) {
			while (h &&
			       (comp_h.time == bin_time)
			       && (comp_h.bin_width == bin_width)
			       && (comp_h.comp_id == comp_id))
				{
				/* Sum message counts for matching patterns */
				if (ptn_id_count) {
					int i;
					for (i = 0; i < ptn_id_count; i++) {
						if (ptn_ids[i] == comp_h.ptn_id) {
							PyObject *comp_ptn_row = make_comp_ptn_row(&comp_h);
							if (comp_ptn_row)
								PyList_Append(comp_ptn_list, comp_ptn_row);
							msg_count += comp_h.msg_count;
							break;
						}
					}
				} else {
					PyObject *comp_ptn_row = make_comp_ptn_row(&comp_h);
					if (comp_ptn_row)
						PyList_Append(comp_ptn_list, comp_ptn_row);
					msg_count += comp_h.msg_count;
				}
				h = bstore_comp_hist_iter_next(comp_iter, &comp_h);
			}
			if (msg_count) {
				struct bcomp_hist_s all_h;
				PyObject *comp_ptn_row;
				all_h.comp_id = comp_id;
				all_h.ptn_id = 1;
				all_h.time = bin_time;
				all_h.msg_count = msg_count;
				comp_ptn_row = make_comp_ptn_row(&all_h);
				if (comp_ptn_row)
					PyList_Append(comp_ptn_list, comp_ptn_row);
			}
		}
	}
 out_0:
	rc = PyDict_SetItemString(hist_dict, "end_time", PyInt_FromLong(last_time));
	rc = PyDict_SetItemString(hist_dict, "min_count", PyInt_FromLong(min_count));
	rc = PyDict_SetItemString(hist_dict, "max_count", PyInt_FromLong(max_count));
	free(comp_ids);
	free(ptn_ids);
	return hist_dict;
 err_4:
	Py_DECREF(comp_ptn_list);
 err_3:
	Py_DECREF(hist_dict);
 err_2:
	free(ptn_ids);
 err_1:
	free(comp_ids);
 err_0:
	return Py_None;
}

Btkn_type_t Tkn_Type_Get(Bstore_t bs, const char *name)
{
	return bstore_tkn_type_get(bs->store, name, strlen(name));
}

%}

typedef void *Bstore_t;
typedef void *Bptn_iter_t;
typedef void *Bmsg_iter_t;
typedef void *Btkn_hist_iter_t;
typedef void *Bptn_hist_iter_t;
typedef void *Bcomp_hist_iter_t;
typedef uint64_t Btkn_type_t;

Bstore_t Open(const char *plugin, const char *path);
void Close(Bstore_t bs);

typedef uint64_t Btkn_id_t;
PyObject *Tkn_Find_By_Id(Bstore_t bs, Btkn_id_t tkn_id);
PyObject *Tkn_Find_By_Name(Bstore_t bs, const char *name, size_t name_len);
Btkn_iter_t Tkn_Iter_New(Bstore_t bs);
void Tkn_Iter_Free(Btkn_iter_t iter);
uint64_t Tkn_Iter_Card(Btkn_iter_t i);
PyObject *Tkn_Iter_First(Btkn_iter_t iter);
PyObject *Tkn_Iter_Find_By_Type(Btkn_iter_t iter, Btkn_type_t type_id);
PyObject *Tkn_Iter_Next(Btkn_iter_t iter);

Bptn_iter_t Ptn_Iter_New(Bstore_t bs);
void Ptn_Iter_Free(Bptn_iter_t iter);
uint64_t Ptn_Iter_Card(Bptn_iter_t i);
typedef uint64_t Bptn_id_t;
PyObject *Ptn_Iter_Find(Bptn_iter_t iter, uint32_t start);
PyObject *Ptn_Iter_Next(Bptn_iter_t iter);
PyObject *Ptn_Iter_Prev(Bptn_iter_t iter);
PyObject *Ptn_Iter_First(Bptn_iter_t iter);
PyObject *Ptn_Iter_Last(Bptn_iter_t iter);

Bmsg_iter_t Msg_Iter_New(Bstore_t bs);
typedef uint64_t Bcomp_id_t;
void Msg_Iter_Free(Bmsg_iter_t i);
uint64_t Msg_Iter_Card(Bmsg_iter_t i);
PyObject *Msg_Iter_Find(Bmsg_iter_t i, Bptn_id_t ptn_id,
			uint32_t start, Bcomp_id_t comp_id);
PyObject *Msg_Iter_Next(Bmsg_iter_t i);
PyObject *Msg_Iter_Prev(Bmsg_iter_t i);
PyObject *Msg_Iter_First(Bmsg_iter_t i);
PyObject *Msg_Iter_Last(Bmsg_iter_t i);

Bptn_tkn_iter_t Ptn_Tkn_Iter_New(Bstore_t bs);
void Ptn_Tkn_Iter_Free(Bptn_tkn_iter_t i);
uint64_t Ptn_Tkn_Iter_Card(Bptn_tkn_iter_t i);
PyObject *Ptn_Tkn_Iter_Find(Bptn_tkn_iter_t iter, Bptn_id_t ptn_id, uint64_t pos);
PyObject *Ptn_Tkn_Iter_Next(Bptn_tkn_iter_t iter);

Btkn_hist_iter_t Tkn_Hist_Iter_New(Bstore_t bs);
void Tkn_Hist_Iter_Free(Btkn_hist_iter_t i);
PyObject *Tkn_Hist_Iter_Find(Btkn_hist_iter_t i, uint64_t tkn_id,
			     uint32_t bin_width, uint32_t time);
PyObject *Tkn_Hist_Iter_Next(Btkn_hist_iter_t i);

Bptn_hist_iter_t Ptn_Hist_Iter_New(Bstore_t bs);
void Ptn_Hist_Iter_Free(Bptn_hist_iter_t i);
PyObject *Ptn_Hist_Iter_Find(Bptn_hist_iter_t i, uint64_t ptn_id,
			     uint32_t bin_width, uint32_t time);
PyObject *Ptn_Hist_Iter_Next(Bptn_hist_iter_t i);

Bcomp_hist_iter_t Comp_Hist_Iter_New(Bstore_t bs);
void Comp_Hist_Iter_Free(Bcomp_hist_iter_t i);
PyObject *Comp_Hist_Iter_Find(Bcomp_hist_iter_t i, uint64_t comp_id,
			      uint32_t bin_width, uint32_t time);
PyObject *Comp_Hist_Iter_Next(Bcomp_hist_iter_t i);

PyObject *Ptn_Hist(Bstore_t bs, PyObject * id_list, uint32_t bin_width,
		   uint32_t start_time, uint32_t end_time);
PyObject *Comp_Hist(Bstore_t bs, PyObject * comp_id_list, PyObject * ptn_id_list,
		    uint32_t bin_width, uint32_t start_time, uint32_t end_time);
PyObject *Comp_Ptn_Hist(Bstore_t bs, PyObject *comp_id_list, PyObject *ptn_id_list,
			uint32_t bin_width, uint32_t start_time, uint32_t end_time);
Btkn_type_t Tkn_Type_Get(Bstore_t bs, const char *name);

PyObject *Tkn_Iter_Pos(Btkn_iter_t iter);
PyObject *Tkn_Iter_Pos_Set(Btkn_iter_t iter, PyObject *py_str);
PyObject *Ptn_Iter_Pos(Bptn_iter_t iter);
PyObject *Ptn_Iter_Pos_Set(Bptn_iter_t iter, PyObject *py_str);
PyObject *Ptn_Tkn_Iter_Pos(Bptn_tkn_iter_t iter);
PyObject *Ptn_Tkn_Iter_Pos_Set(Bptn_tkn_iter_t iter, PyObject *py_str);
PyObject *Tkn_Hist_Iter_Pos(Btkn_hist_iter_t iter);
PyObject *Tkn_Hist_Iter_Pos_Set(Btkn_hist_iter_t iter, PyObject *py_str);
PyObject *Ptn_Hist_Iter_Pos(Bptn_hist_iter_t iter);
PyObject *Ptn_Hist_Iter_Pos_Set(Bptn_hist_iter_t iter, PyObject *py_str);
PyObject *Comp_Hist_Iter_Pos(Bcomp_hist_iter_t iter);
PyObject *Comp_Hist_Iter_Pos_Set(Bcomp_hist_iter_t iter, PyObject *py_str);
