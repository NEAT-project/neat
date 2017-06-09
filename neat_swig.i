/* NEAT declarations for SWIG */
%module neat
%include "stdint.i" /* Convert uint16_t correctly */
%{
#include "neat.h"
%}

%{
static __thread PyObject *callback;
static neat_error_code dispatcher(struct neat_flow_operations *ops) {
    PyObject *pyops = SWIG_NewPointerObj(SWIG_as_voidptr(ops), SWIGTYPE_p_neat_flow_operations, SWIG_POINTER_NEW |  0 );
    PyObject *res = PyObject_CallFunctionObjArgs(callback, pyops, NULL);
    unsigned long long val = PyLong_AsUnsignedLongLong(res);
    return (neat_error_code)(val);
}
%}


%typemap(in) neat_error_code(*)(struct neat_flow_operations *) {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    }
    $1 = dispatcher;
    callback = $input;
}

%include "neat.h"

