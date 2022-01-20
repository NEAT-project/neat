#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <jansson.h>

#include "pm_helper.h"

typedef struct var_stack_entry {
    double value;
    struct var_stack_entry *next;
} var_stack_t;

typedef struct op_stack_entry {
    char value;
    struct op_stack_entry *next;
} op_stack_t;

var_stack_t *var;
op_stack_t *op;

op_stack_t *
op_init()
{
    op_stack_t *entry = malloc(sizeof(op_stack_t));

    entry->value = '\0';
    entry->next = NULL;

    return entry;
}

/* Push entry onto stack */
void 
op_push(char c) 
{
    op_stack_t *entry = op_init();

    entry->value = c;
    entry->next = op;

    op = entry;
}

char 
op_pop()
{
    op_stack_t *tmp = op->next;
    char c = op->value;
    free(op);
    op = tmp;

    return c;
}

void 
op_delete() 
{
    op_stack_t *tmp;

    while (op != NULL) {
        tmp = op;
        op = op->next;
        free(tmp);
    }
}

var_stack_t *
var_init() 
{
    var_stack_t *entry = malloc(sizeof(var_stack_t));

    entry->value = 0;
    entry->next = NULL;

    return entry;
}

/* Push entry onto stack */
void 
var_push(double d) 
{
    var_stack_t *entry = var_init();

    entry->value = d;
    entry->next = var;

    var = entry;
}

double 
var_pop() 
{
    var_stack_t *tmp = var->next;
    double d = var->value;
    free(var);
    var = tmp;

    return d;
}

void
var_delete() 
{
    var_stack_t *tmp;

    while (var != NULL) {
        tmp = var;
        var = var->next;
        free(tmp);
    }
}

int
isop(char c)
{
    return c == '+' || c == '-' || c == '*' || c == '/';
}

int 
priority (char c) 
{
    if (c == '+' || c == '-')
        return 1;
    if (c == '*' || c == '/')
        return 2;
    return -1;
}

int
process_op(char c) 
{
    if (var && var->next) {
        double r = var_pop();
        double l = var_pop();

        switch (c)
        {
        case '+': var_push(l + r); break;
        case '-': var_push(l - r); break;
        case '*': var_push(l * r); break;
        case '/':
            if (r == 0) {
                write_log(__FILE__, __func__, LOG_DEBUG, "error: division by zero\n");
                return -1;
            }

            var_push(l / r); 
            break;
        default: break;
        }
    }

    return 0;
}

int issymbol(int c) {
    if (c >= 33 && c <= 35) {
        return 1;
    }

    if (c >= 37 && c <= 39) {
        return 1;
    }

    if (c == 44) {
        return 1;
    }

    if (c == 46) {
        return 1;
    }

    if (c >= 58 && c <= 64) {
        return 1;
    }

    if (c >= 91 && c <= 96) {
        return 1;
    }

    if (c >= 123 && c <= 126) {
        return 1;
    }

    return 0;
}

int 
eval(const char *expr, json_t *json) 
{
    char c, p;
    int i = 0;

    p = expr[0];
    while (p != '\0') {
        if (p == '(') {
            op_push(p);
        } else if (p == ')') {
            /* Eval all the way up here */
            while (op && op->value != '(') {
                c = op_pop();
                if (process_op(c) < 0) {
                    return -1;
                } 
            }
            if (op) {
                op_pop();
            }
        } else if (isop(p)) {
            /* If operator */;
            if (op) {
                /* evaluate whatever we have so far */
                while (op && priority(op->value) >= priority(p)) { 
                    c = op_pop();
                    if (process_op(c) < 0) {
                        return -1;
                    } 
                }
            }
            op_push(p);
        } else if (isalpha(p)) {
            int count = 0, start = i;
            /* parse the entire identifier */
            while(isalnum(p) || issymbol(p)) {
                i++;
                p = expr[i];
            }
            count = i - start;
            i--;
            char v[count+1];
            strncpy(v, expr+start, count);
            v[count] = '\0';

            /* get value from identifier */            
            json_t *id = json_object_get(json_object_get(json, v), "value");
            if (!id || !json_is_number(id)) {
                write_log(__FILE__, __func__, LOG_DEBUG, "syntax error: unknown identifier: '%s'\n", v);
                return -1;
            }

            double num = json_number_value(id);            
            var_push(num);
        } else if (isdigit(p)) {
            /* Is number */
            double num = 0;
            double dec = 0;
            int decimals = 0;

            while (p != '\0' && (isdigit(p) || p == '.')) {
                if (p == '.') {
                    if (decimals > 0) {
                        write_log(__FILE__, __func__, LOG_DEBUG, "syntax error: unexpected character: '%c'\n", p);
                        return -1;
                    }
                    decimals = 1;
                } else if (decimals) {
                    dec = dec + (p - '0') * pow(0.1, decimals);
                    decimals++;
                } else {
                    num = num * 10 + p - '0';
                }

                i++;
                p = expr[i];
            }
            --i;

            num = num + dec;
            var_push(num);
        } else if (!isspace(p)) {
            /* Invalid character */
            write_log(__FILE__, __func__, LOG_DEBUG, "syntax error: unexpected character: '%c'\n", p);
            return -1;
        }

        i++;
        p = expr[i];
    }

    while(op) {
        char c = op_pop();
        if (process_op(c) < 0) {
            return -1;
        } 
    }

    return 1;
}

int 
parse(const char *expr, json_t *json, double *res) 
{
    /* Init */
    int err, ret = -1;
    var = NULL;
    op = NULL;

    /* Evaluate */
    if (eval(expr, json) > 0 && var) {
        *res = var->value;
        ret = 1;
    }
    /* Cleanup */
    op_delete();
    var_delete();

    return ret; 
}

int
parse_string(const char *expr, json_t *json, char **res)
{
    char *s;
    json_t *prop, *value;

    /* 
     * Don't do anything fancy for now, 
     * just allow one string property to be copied to another
     */

    // Get the name of the property
    size_t len = strlen(expr);
    s = calloc(1, len);
    strncpy(s, expr, len-1);
    prop = json_object_get(json, s);
    free(s);

    if (!json_is_object(prop))
        return -1;

    value = json_object_get(prop, "value");

    if (!json_is_string(value))
        return -1;

    // Copy value
    const char *val = json_string_value(value); 
    len = strlen(val);

    *res = calloc(1, len + 1);
    strncpy(*res, val, len);

    return 1;
}

int 
evaluate_property(json_t *properties, json_t *prop, char *type) 
{
    const char *str;
    json_t *val = json_object_get(prop, type);
    if (json_is_string(val)) {
        str = json_string_value(val);
        if (str) {
            size_t len = strlen(str);
            if (len <= 3) /* Invalid func */{
                return 1;
            }

            /* 
             * Integer functions have format i(...)
             * Float functions have format f(...)
             * String functions have format s(...)
             */ 
            if (str[0] == 'i' && str[1] == '(' && str[len - 1] == ')') {
                /* This is an integer function */
                double res = 0;
                
                if(parse(str+1, properties, &res) > 0) {
                    json_object_set_new(prop, type, json_integer(res));
                }
            }

            if (str[0] == 'f' && str[1] == '(' && str[len - 1] == ')') {
                /* This is a numerical function */
                double res = 0;
                
                if(parse(str+1, properties, &res) > 0) {
                    json_object_set_new(prop, type, json_real(res));
                }
            }

            if (str[0] == 's' && str[1] == '(' && str[len - 1] == ')') {
                /* This is a string function */
                char *res = NULL;
                
                if(parse_string(str+2, properties, &res) > 0) {
                    json_object_set_new(prop, type, json_string(res));
                    free(res);
                }
            }

        }
    }

    return 0;
}

/* Evaluate functions in a property object */
int
evaluate_funcs(json_t *json) {
    json_t *val, *prop;
    const char *key;

    json_object_foreach(json, key, prop) {
        evaluate_property(json, prop, "value");
        evaluate_property(json, prop, "score");
    }

    return 0;
}
