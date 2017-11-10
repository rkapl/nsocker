#include <Python.h>
#include <nsocker/client.h>

static void free_ctx(ns_context *ctx)
{
	ns_client_free(ctx->socket_client);
	free(ctx->socket_client);
	free(ctx);
}

static PyObject *nsocker_push(PyObject *self, PyObject *args)
{
    const char *path;

    if (!PyArg_ParseTuple(args, "s", &path))
	return NULL;

    ns_context *ctx = malloc(sizeof(*ctx));
    ns_client *c = malloc(sizeof(*c));
    if (!c || !ctx)
	    abort();

    ns_client_init(c);
    if (!ns_client_connect(c, path)) {
	    free_ctx(ctx);
	    return PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
    }

    if(!ns_push(ctx))
	    abort();
    ctx->pop_cb = free_ctx;
    ctx->user = NULL;
    ctx->socket_client = c;

    Py_RETURN_NONE;
}

static PyObject *nsocker_pop(PyObject *self, PyObject *args)
{
	ns_pop(NULL);
	Py_RETURN_NONE;
}

static PyMethodDef modmethods[] = {
	{"push",  nsocker_push, METH_VARARGS, "Connect to a nsocker server"},
	{"pop",  nsocker_pop, METH_VARARGS, "Connect to a nsocker server"},
	{NULL, NULL, 0, NULL}        /* Sentinel */
};

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef moduledef = {
	PyModuleDef_HEAD_INIT,
	"nsocker",
	NULL,
	0,
	modmethods,
	NULL,
	NULL,
	NULL,
	NULL
};
#else
#endif


PyMODINIT_FUNC PyInit_nsocker(void)
{
#if PY_MAJOR_VERSION >= 3
	return PyModule_Create(&moduledef);
#else
	Py_InitModule("nsocker", modmethods);
#endif

}
