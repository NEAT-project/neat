/* NEAT declarations for SWIG */
%module neat

%include "stdint.i" /* Convert uintXX_t correctly */
%include "typemaps.i"
%include "cpointer.i"
%include "carrays.i"

%{
#include "neat.h"
%}

%{
static struct {
    PyObject *on_connected;
    PyObject *on_error;
    PyObject *on_readable;
    PyObject *on_writable;
    PyObject *on_all_written;
    PyObject *on_network_status_changed;
    PyObject *on_aborted;
    PyObject *on_timeout;
    PyObject *on_close;
    PyObject *on_parameters;

    PyObject *on_send_failure;
    PyObject *on_slowdown;
    PyObject *on_rate_hint;
} py_callbacks ;

static neat_error_code dispatch_fx(struct neat_flow_operations *ops, PyObject *pyfunc) {
    PyObject *pyops = SWIG_NewPointerObj(SWIG_as_voidptr(ops), SWIGTYPE_p_neat_flow_operations, 0 |  0 );
    PyObject *res = PyObject_CallFunctionObjArgs(pyfunc, pyops, NULL);
    unsigned long val = PyLong_AsUnsignedLong(res);
    return (neat_error_code)(val);
}

static neat_error_code disp_on_connected(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_connected);
}
static neat_error_code disp_on_error(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_error);
}
static neat_error_code disp_on_readable(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_readable);
}
static neat_error_code disp_on_writable(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_writable);
}
static neat_error_code disp_on_all_written(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_all_written);
}
static neat_error_code disp_on_network_status_changed(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_network_status_changed);
}
static neat_error_code disp_on_aborted(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_aborted);
}
static neat_error_code disp_on_timeout(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_timeout);
}
static neat_error_code disp_on_close(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_close);
}
static neat_error_code disp_on_parameters(struct neat_flow_operations *ops) {
    return dispatch_fx(ops, py_callbacks.on_parameters);
}

static void dispatch_send_failure(struct neat_flow_operations *ops, int context, const unsigned char *unsent) {
    PyObject *pyfunc = py_callbacks.on_send_failure;
    PyObject *pyops = SWIG_NewPointerObj(SWIG_as_voidptr(ops), SWIGTYPE_p_neat_flow_operations, 0 |  0 );
    PyObject *pyctx = PyInt_FromLong(context);
    PyObject *pymsg = PyString_FromString((const char *) unsent);
    PyObject_CallFunctionObjArgs(pyfunc, pyops, pyctx, pymsg, NULL);
}

static void dispatch_slowdown(struct neat_flow_operations *ops, int ecn, uint32_t rate) {
    PyObject *pyfunc = py_callbacks.on_slowdown;
    PyObject *pyops = SWIG_NewPointerObj(SWIG_as_voidptr(ops), SWIGTYPE_p_neat_flow_operations, 0 |  0 );
    PyObject *pyecn = PyInt_FromLong(ecn);
    PyObject *pyrate = PyInt_FromLong(rate);
    PyObject_CallFunctionObjArgs(pyfunc, pyops, pyecn, pyrate, NULL);
}

static void dispatch_rate_hint(struct neat_flow_operations *ops, uint32_t rate) {
    PyObject *pyfunc = py_callbacks.on_slowdown;
    PyObject *pyops = SWIG_NewPointerObj(SWIG_as_voidptr(ops), SWIGTYPE_p_neat_flow_operations, 0 |  0 );
    PyObject *pyrate = PyInt_FromLong(rate);
    PyObject_CallFunctionObjArgs(pyfunc, pyops, pyrate, NULL);
}

%}


%typemap(in) neat_flow_operations_fx {
    if ($input == Py_None) { /* Unset a callback function */
        $1 = NULL;
        py_callbacks.$1_name = NULL;
    } else if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    } else {
        $1 = disp_$1_name;
        py_callbacks.$1_name = $input;
    }
}

%typemap(in) neat_cb_send_failure_t {
    if ($input == Py_None) { /* Unset a callback function */
        $1 = NULL;
        py_callbacks.$1_name = NULL;
    } else if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    } else {
        $1 = dispatch_send_failure;
        py_callbacks.$1_name = $input;
    }
}

%typemap(in) neat_cb_flow_slowdown_t {
    if ($input == Py_None) { /* Unset a callback function */
        $1 = NULL;
        py_callbacks.$1_name = NULL;
    } else if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    } else {
        $1 = dispatch_slowdown;
        py_callbacks.$1_name = $input;
    }
}

%typemap(in) neat_cb_flow_rate_hint_t {
    if ($input == Py_None) { /* Unset a callback function */
        $1 = NULL;
        py_callbacks.$1_name = NULL;
    } else if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    } else {
        $1 = dispatch_rate_hint;
        py_callbacks.$1_name = $input;
    }
}

%typemap(in) const unsigned char *buffer {
    $1 = (unsigned char*) PyString_AsString($input);
}

//%typemap(in) (void *) {
//    $1 = (void *) $input;
//};

%pointer_functions(uint32_t, uint32_tp);

%pointer_functions(size_t, size_tp);



%array_class(unsigned char, charArr);

%include "neat.h"

