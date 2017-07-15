/* NEAT declarations for SWIG */
%module neat
%include "stdint.i" /* Convert uint16_t correctly */
%{
#include "neat.h"
%}

%{
static __thread struct {
    PyObject *on_connected;
    PyObject *on_error;
    PyObject *on_readable;
    PyObject *on_writable;
    PyObject *on_all_written;
    PyObject *on_network_status_changed;
    PyObject *on_aborted;
    PyObject *on_timeout;
    PyObject *on_close;
} py_callbacks ;

static neat_error_code dispatcher(struct neat_flow_operations *ops, PyObject *pyfunc) {
    PyObject *pyops = SWIG_NewPointerObj(SWIG_as_voidptr(ops), SWIGTYPE_p_neat_flow_operations, 0 |  0 );
    PyObject *res = PyObject_CallFunctionObjArgs(pyfunc, pyops, NULL);
    unsigned long long val = PyLong_AsUnsignedLongLong(res);
    return (neat_error_code)(val);
}

static neat_error_code disp_on_connected(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_connected);
}
static neat_error_code disp_on_error(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_error);
}
static neat_error_code disp_on_readable(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_readable);
}
static neat_error_code disp_on_writable(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_writable);
}
static neat_error_code disp_on_all_written(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_all_written);
}
static neat_error_code disp_on_network_status_changed(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_network_status_changed);
}
static neat_error_code disp_on_aborted(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_aborted);
}
static neat_error_code disp_on_timeout(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_timeout);
}
static neat_error_code disp_on_close(struct neat_flow_operations *ops) {
    return dispatcher(ops, py_callbacks.on_close);
}
%}


%typemap(in) neat_flow_operations_fx {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    }
    $1 = disp_$1_name;
    py_callbacks.$1_name = $input;
}

%include "neat.h"

