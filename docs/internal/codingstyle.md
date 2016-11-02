# Coding Style

The coding style used in NEAT is based on the
[coding style used in the Linux kernel](https://www.kernel.org/doc/Documentation/CodingStyle).
There are, however, some differences between the kernel style and the style used in the NEAT project.
This document details these differences.

### Strictness

This coding style serves as a guideline. Adherence is not strictly required,
but (new) code should still try to follow these guidelines as far as possible
to ensure that the code in the NEAT library has a coherent style.

### Disambiguation

If some piece of code does not follow these guidelines, try to match the
surrounding code. Do not mix style changes into commits with a different purpose.

### Indentation

4 spaces.

### Line length

There is no strict limit on the length of a line. As a general guideline, try
to keep it below 120 characters.

### Placement of braces

Generally the same as the Linux kernel style.

Braces may be used for blocks containing only one statement. Be consistent in
adjacent blocks.

**Yes**:
```c
if (this) {
    do_that();
} else {
    something();
}
```

**No**:
```c
if (this) {
    do_that();
} else
    something();
```

### Spaces

As in the Linux kernel style.

Please avoid trailing whitespace.

### Naming

Use names separated by underscores, e.g. `this_is_my_variable`.

Descriptive names are preferred, but short, well-known abbreviations are
acceptable.

### Functions

The return type is placed on a separate line preceding the function name:

```c
void
my_function(int parameter1, int parameter2)
{

}
```

Align parameters on subsequent lines with the first parameter:

```c
void
my_other_function(int parameter1, int parameter2, ...
                  int parameterN, int parameterM)
{

}
```

### Tools

The `.editorconfig` file in the NEAT repository can be used by most editors
with the help of a plugin. See [www.editorconfig.org](http://www.editorconfig.org/).

The `uncrustify-neat.cfg` file can be used by the Uncrustify tool to format
source code in accordance with this NEAT style guide. See the Uncrustify
documentation for more information.
