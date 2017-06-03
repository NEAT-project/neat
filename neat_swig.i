/* NEAT declarations for SWIG */
%module neat
%include "stdint.i" /* Convert uint16_t correctly */
%{
#include "neat.h"
%}

%typemap(in) neat_flow_operations_fx {
    if (!PyCallable_Check($input)) {
        PyErr_SetString(PyExc_TypeError, "Need a callable object!");
        return NULL;
    }
    $1 = (neat_flow_operations_fx) PyInt_AsLong($input);
}

%include "neat.h"

