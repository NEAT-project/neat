#include <jansson.h>
#include <string.h>

#include "parse_json.h"
#include "pm_helper.h"
#include "pm_utils.h"
#include "opts.h"

#define MAX(a,b) (((a)>(b))?(a):(b))
#define ARRAY_SIZE(array) (sizeof((array))/sizeof((array)[0]))

typedef struct score_struct {
    int evaluated;
    int non_evaluated;
} score_t;

/* returns 1 if value is "Inf" or "inf", -1 if value is "-Inf" or "-inf", else returns 0 */
int
parse_inf(json_t *value)
{
    const char *s;
    if(s = json_string_value(value)) {
        char lwr[10];
        if(strnlwr(lwr, s, 9)) {
            if(!strcmp(lwr, "inf") || !strcmp(lwr, "infinity")) {
                return 1;
            }
            if(!strcmp(lwr, "-inf") || !strcmp(lwr, "-infinity")) {
                return -1;
            }
        }
    }

    return 0;
}

RANGE_TYPE
parse_range(json_t *start, json_t *end) 
{
    if(json_is_number(start) && json_is_number(end)) {
        if(json_number_value(start) >= json_number_value(end)) {
            write_log(__FILE__, __func__, LOG_ERROR, "Invalid range.");
            return RANGE_TYPE_ERR;
        }
        return RANGE_TYPE_BOUNDED;
    } 
    else if(parse_inf(start) < 0 && json_is_number(end)) {
        return RANGE_TYPE_NO_LOWER_BOUND;
    } 
    else if(json_is_number(start) && parse_inf(end) > 0) {
        return RANGE_TYPE_NO_UPPER_BOUND;
    } 
    else if (parse_inf(start) < 0 && parse_inf(end) > 0) {
        return RANGE_TYPE_UNBOUNDED;
    } 
    else {
        write_log(__FILE__, __func__, LOG_ERROR, "Invalid range.");
        return RANGE_TYPE_ERR;
    }
}

bool
is_single(json_t *value) 
{
    return !json_is_object(value) && !json_is_array(value);
}

bool
is_set(json_t *value) 
{
    if(json_is_array(value)) {
        return true;
    }
    return false;
}

bool
is_range(json_t *value) 
{
    json_t *start = json_object_get(value, "start");
    json_t *end = json_object_get(value, "end");

    return start && end;
}

bool
is_null(json_t *value) 
{
    return json_is_null(value);
}

VALUE_TYPE
type(json_t *value) 
{
    if (is_null(value)) {
        return VALUE_TYPE_NULL;
    }
    return is_null(value) ? VALUE_TYPE_NULL : is_set(value) ? VALUE_TYPE_SET \
        : is_range(value) ? VALUE_TYPE_RANGE : is_single(value) ? VALUE_TYPE_SINGLE : VALUE_TYPE_ERR;
}

bool
pre_resolve(const json_t *requests)
{
    bool pre_resolve = false;
    json_t *request;
    size_t i;

    json_array_foreach(requests, i, request) {
        json_t *req_type = json_object_get(request, "__request_type");
        if (req_type) {
            const char *req_type_val = json_string_value(json_object_get(req_type, "value"));
            if (!strcmp(req_type_val, "pre-resolve")) {
                json_object_del(request, "__request_type");
                pre_resolve = true;
            }
        }

    }
    return pre_resolve;
}

void
add_default_values(json_t *request)
{
    json_t *property, *attr;
    const char *key;
    size_t n;
    unsigned int i;

    /* json values for default props */
    char *default_props[] = { "value", "score", "evaluated", "precedence"};
    char *default_types[] = { "n", "i", "b", "i"};
    int  default_values[] = { 0, 0, 0, PRECEDENCE_OPTIONAL };

    json_object_foreach(request, key, property) {
        for (i = 0; i < ARRAY_SIZE(default_props); i++) {

            /* handle array of values */
            if (json_is_array(property)) {
                json_array_foreach(property, n, attr) {
                    json_t *tmp_prop = json_pack("{sO}", key, attr);
                    add_default_values(tmp_prop);
                    json_decref(tmp_prop);
                }
                break;
            }
            /* add default property if not found */
            if (json_object_get(property, default_props[i]) == NULL) {
                json_object_set_new(property, default_props[i], json_pack(default_types[i], default_values[i]));
            }
        }
    }
}

score_t
property_score_sum(json_t *candidate)
{
    score_t sum = {0};
    int score;
    const char *key;
    json_t *property;
    json_t *score_obj;
    json_t *eval_obj;

    json_object_foreach(candidate, key, property) {
        score_obj = json_object_get(property, "score");
        if (score_obj) {
            score = json_integer_value(score_obj);
            eval_obj = json_object_get(property, "evaluated");
            if (eval_obj && json_is_true(eval_obj)) {
                sum.evaluated += score;
            }
            else {
                sum.non_evaluated += score;
            }
        }
    }
    return sum;
}

int
cmp_score(const void *json1, const void *json2)
{
    score_t score1 = property_score_sum(*((json_t **) json1));
    score_t score2 = property_score_sum(*((json_t **) json2));

    int evaluated_diff = score2.evaluated - score1.evaluated;
    int non_evaluated_diff = score2.non_evaluated - score1.non_evaluated;

    /* evaluated > non_evaluated */
    return evaluated_diff != 0 ? evaluated_diff : non_evaluated_diff;
}

json_t *
sort_json_array(json_t *array)
{
    size_t arr_size = json_array_size(array);
    json_t *to_sort[arr_size];
    json_t *result = json_array();
    json_t *item;
    size_t i;

    json_array_foreach(array, i, item) {
        to_sort[i] = item;
    }

    qsort(to_sort, arr_size, sizeof(json_t *), cmp_score);

    for (i = 0; i < arr_size; i++) {
        json_array_append_new(result, to_sort[i]);
    }
    json_decref(array);

    return result;
}

/* return the first n elements of array defined by limit */
json_t *
limit_json_array(json_t *array, const unsigned int limit)
{
    size_t arr_size = json_array_size(array);
    size_t i;

    if(arr_size == 0) { return array; }

    for (i = arr_size - 1; i >= limit; i--) {
        if (json_array_remove(array, i) == -1) {
            write_log(__FILE__, __func__, LOG_ERROR, "Failed to remove array element during parsing.");
        }
    }
    return array;
}

void
append_json_arrays(json_t *root_array, json_t *array)
{
    size_t index;
    json_t *value;

    json_t * new_array = create_json_array(array);

    json_array_foreach(new_array, index, value) {
        json_array_append(root_array, value);
    }
    json_decref(new_array);
}

json_t*
parse_local_endpoint(json_t *local_endpoint, json_t *element)
{
    json_t* value = json_object_get(local_endpoint, "value");

    if(!json_is_null(value)) {
        char *le_value = strdup(json_string_value(value));
        if(strchr(le_value, '@')) {
            char * ip_value = strtok(le_value, "@");
            char * interface_value = strtok(NULL, "@");

            json_t *local_ip = json_deep_copy(local_endpoint);
            json_object_set_new(local_ip, "value", json_string(ip_value));

            json_t *interface = json_deep_copy(local_endpoint);
            json_object_set_new(interface, "value", json_string(interface_value));

            json_object_set_new(element, "interface", interface);
            json_object_set_new(element, "local_ip", local_ip);
            json_object_del(element, "local_endpoint");
        }
        free(le_value);
    }
    return element;
}

json_t*
create_json_array(json_t *json) {
    if(json_is_array(json)) { return json; }

    json_t *root;
    root = json_array();
    json_array_append_new(root, json);
    return root;
}

json_t*
process_special_properties(json_t* req)
{
    size_t index;
    json_t *value;
    json_t *root = create_json_array(req);
    json_t *my_return = json_array();

    json_array_foreach(root, index, value) {
        json_t * local_endpoint = json_object_get(value, "local_endpoint");

        if(local_endpoint && json_is_object(local_endpoint)) {
            append_json_arrays(my_return, parse_local_endpoint(local_endpoint, value));
        }
        else {
            json_array_append(my_return, value);
        }
    }
    json_decref(root);
    return my_return;
}


void
convert_socket_properties(json_t *candidate_array) 
{
    size_t index;
    json_t *candidate;
    json_t *property;
    json_t *new_properties;

    char *new_key;
    const char *key;
    void *tmp;

    json_array_foreach(candidate_array, index, candidate) {
        new_properties = json_object();
        json_object_foreach_safe(candidate, tmp, key, property) {
            char *prop = malloc(strlen(key) + 1);
            if(prop) {
                strnupr(prop, key, strlen(key));
                new_key = sock_prop(prop);
                free(prop);

                if(new_key) {
                    json_object_set_new(new_properties, new_key, json_copy(property));
                    json_object_del(candidate, key);
                    free(new_key); 
                }
            }
        }
        json_object_foreach(new_properties, key, property) {
            json_object_set(candidate, key, property);
        } 
        json_decref(new_properties);
    }
}

void
append_value(json_t *json, json_t *new_value)
{
    if(json_is_array(new_value)) {
        size_t index;
        json_t *value;
        json_array_foreach(new_value, index, value) {
            json_array_append(json, value);
        }
    }
    else if(json_is_object(new_value)) {
        json_object_update(json, new_value);
    }
    else {
        write_log(__FILE__, __func__, LOG_ERROR, "Failed to parse json.");
        if(debug_enabled) {
            char* json_string = json_dumps(new_value, 0);
            write_log(__FILE__, __func__, LOG_DEBUG, "Failed to parse: \n%s.\n", json_string);
            free(json_string);
        }
    }
}

// Expands a 2D array into a 1D array
json_t*
expand_json_arrays(json_t *in_properties)
{
    json_t *result, *temp1, *temp2;
    result = json_array();
    temp1 = json_array();

    if(in_properties == NULL || json_is_null(in_properties)) { return result; }

    json_array_append_new(result, temp1);
    size_t index1, index2, index3;
    json_t *value1, *value2, *value3;

    json_array_foreach(in_properties, index1, value1) {
        temp1 = json_array();
        json_array_foreach(value1, index2, value2) {
            json_array_foreach(result, index3, value3) {
                temp2 = json_object();
                append_value(temp2, value3);
                append_value(temp2, value2);
                json_array_append_new(temp1, temp2);
            }
        }
        json_decref(result);
        result = temp1;
    }
    return result;
}

// Expands a json object/1D array/2D array into a 1D array
json_t*
expand_json(json_t *in_properties)
{
    json_t *result;
    result = json_array();

    if(in_properties == NULL || json_is_null(in_properties)) {
        return result;
    }
    else if(json_is_object(in_properties)) {
        /* json is an object, convert into 1D array */
        json_array_append(result, in_properties);
        return result;
    }
    else if(json_is_array(in_properties)) {
        if( json_array_size(in_properties) > 0 && json_is_array(json_array_get(in_properties, 0))) {
            /* json is a 2D array - expand arrays into a 1D array */
            json_decref(result);
            return expand_json_arrays(in_properties);
        }
        else {
            /* json already a 1D array - nothing to do */
            json_decref(result);
            return json_copy(in_properties);
        }
    }
    write_log(__FILE__, __func__, LOG_ERROR, "Unknown json structure.");
    return result;
}

/* NEEDS REFACTORING: Variant of expand_element_property which dereferences element */
json_t*
expand_element_property_decref(json_t *element)
{
    const char *key;
    json_t *property;
    json_t *my_return = json_array();

    json_object_foreach(element, key, property) {
        if(json_is_array(property)) {
            append_json_arrays(my_return, expand_property(element, property, key));
            break;   //break here due to loop call in expand_property
        }
    }

    if(json_array_size(my_return) == 0) {
        json_array_append(my_return, element);
    } else {
        json_decref(element);
    } 
    return my_return;
}

json_t*
expand_property(json_t *element, json_t *property_input, const char *key)
{
    size_t index1;
    json_t *value;
    json_t *my_return = json_array();

    json_array_foreach(property_input, index1, value) {
        json_t *temp = json_deep_copy(element);
        json_object_set(temp, key, value);
        append_json_arrays(my_return, expand_element_property_decref(temp));    //loop call
    }

    return my_return;
}

json_t*
expand_element_property(json_t *element)
{
    const char *key;
    json_t *property;
    json_t *my_return = json_array();

    json_object_foreach(element, key, property) {
        if(json_is_array(property)) {
            append_json_arrays(my_return, expand_property(element, property, key));
            break;   //break here due to loop call in expand_property
        }
    }

    if(json_array_size(my_return) == 0) {
        json_array_append(my_return, element);
    }
    return my_return;
}

json_t*
expand_properties(json_t *req)
{
    size_t index;
    json_t *element;
    json_t *root = create_json_array(req);
    json_t *my_return = json_array();

    json_array_foreach(root, index, element) {
        if(json_is_object(element)) {
            json_t *temp = json_deep_copy(element);
            append_json_arrays(my_return, expand_element_property(temp));
            json_decref(temp);
        }
        else {
            write_log(__FILE__, __func__, LOG_ERROR, "Invalid json format, parsing failed.");
        }
    }
    json_decref(root);
    return my_return;
}

json_t*
expand_value(json_t *element, json_t *property, json_t *value_input, const char *key)
{
    size_t index1;
    json_t* v;
    json_t* my_return = json_array();
    json_t* value = json_deep_copy(value_input);

    //create a new element for every element in the value
    json_array_foreach(value, index1, v) {
        json_t* temp_ele = json_deep_copy(element);
        json_t* temp_prop = json_object_get(temp_ele, key);
        json_object_set(temp_prop, "value", v);
        json_object_set(temp_ele, key, temp_prop);
        append_json_arrays(my_return, temp_ele);    //loop call
    }
    json_decref(value);

    return my_return;
}

json_t*
expand_element_value(json_t *element)
{
    const char *key;
    json_t *property;
    json_t *my_return = json_array();

    json_object_foreach(element, key, property) {
        if(json_is_object(property)) {
            json_t* value = json_object_get(property, "value");
            if(value != 0 && json_is_array(value)) {
                append_json_arrays(my_return, expand_value(element, property, value, key));
                break;   //break here due to loop call in expand_value
            }
        }
    }

    if(json_array_size(my_return) == 0) {
        json_array_append(my_return, element);
    }
    return my_return;
}


json_t*
expand_values(json_t *req)
{
    size_t index;
    json_t *element;
    json_t *root = create_json_array(req);
    json_t *my_return = json_array();

    json_array_foreach(root, index, element) {
        if(json_is_object(element)) {
            append_json_arrays(my_return, expand_element_value(element));
        }
        else {
            write_log(__FILE__, __func__, LOG_ERROR, "Invalid json format, parsing failed.");
        }
    }
    json_decref(root);
    return my_return;
}

/* returns true if value_a equals value_b */
bool
match_single_single(json_t *value_a, json_t *value_b) {
    return json_equal(value_a, value_b);
}

/* returns true if the single value_a is in the set value_b */
bool
match_single_set(json_t *value_a, json_t *value_b) {
    json_t *value;
    size_t i;

    json_array_foreach(value_b, i, value) {
        if(json_equal(value, value_a)) {
            return true;
        }
    }
    return false;
}

/* returns true if the single value_a is in the range value_b */
bool
match_single_range(json_t *value_a, json_t *value_b) {
    if(!json_is_number(value_a)) {
        return false;
    }

    double single = json_number_value(value_a);
    double start, end;
    json_t *start_obj = json_object_get(value_b, "start");
    json_t *end_obj = json_object_get(value_b, "end");
    int inf;

    switch(parse_range(start_obj, end_obj))
    {
        case RANGE_TYPE_BOUNDED:
            /* start <= single <= end */
            start = json_number_value(start_obj);
            end = json_number_value(end_obj);
            return start <= single && single <= end;
        case RANGE_TYPE_NO_LOWER_BOUND:
            /* -inf <= single <= end */
            end = json_number_value(end_obj);
            return single <= end;
        case RANGE_TYPE_NO_UPPER_BOUND:
            /* start <= single <= inf */
            start = json_number_value(start_obj);
            return start <= single;
        case RANGE_TYPE_UNBOUNDED:
            /* -inf <= single <= inf */
            return true;
        default:
            return false;
    }
}

/* returns true if the set value_a is a subset of the set value_b */
bool
match_set_set(json_t *value_a, json_t *value_b) {
    json_t *value;
    size_t i;

    int matches = 0;
    json_array_foreach(value_a, i, value) {
        if(match_single_set(value, value_b)) {
            matches++;
        }
    }

    return matches == i ? true : false;
}

/* returns true if the set value_a is in the range value_b */
bool
match_set_range(json_t *value_a, json_t *value_b) {
    json_t *value;
    size_t i;

    json_array_foreach(value_a, i, value) {
        if(!match_single_range(value, value_b)) { 
            return false;
        }
    }

    return true;
}

/* returns true if the range value_a is in the range value_b */
bool
match_range_range(json_t *value_a, json_t *value_b) {
    double start_a;
    double end_a;
    double start_b;
    double end_b;

    json_t *start_obj_a = json_object_get(value_a, "start");
    json_t *start_obj_b = json_object_get(value_b, "start");

    json_t *end_obj_a = json_object_get(value_a, "end");
    json_t *end_obj_b = json_object_get(value_b, "end");

    switch(parse_range(start_obj_a, end_obj_a))
    {
        case RANGE_TYPE_BOUNDED:
            switch(parse_range(start_obj_b, end_obj_b))
            {
                case RANGE_TYPE_BOUNDED:
                    /* value_a: (x, y), value_b: (z, w) */
                    start_a = json_number_value(start_obj_a);
                    start_b = json_number_value(start_obj_b);
                    end_a = json_number_value(end_obj_a);
                    end_b = json_number_value(end_obj_b);
                    return start_b <= start_a && end_a <= end_b;
                case RANGE_TYPE_NO_LOWER_BOUND:
                    /* value_a: (x, y), value_b: (-inf, w) */
                    end_a = json_number_value(end_obj_a);
                    end_b = json_number_value(end_obj_b);
                    return end_a <= end_b;
                case RANGE_TYPE_NO_UPPER_BOUND:
                    /* value_a: (x, y), value_b: (z, inf) */
                    start_a = json_number_value(start_obj_a);
                    start_b = json_number_value(start_obj_b);
                    return start_b <= start_a;
                case RANGE_TYPE_UNBOUNDED:
                    /* value_a: (x, y), value_b: (-inf, inf) */
                    return true;
                default:
                    return false;
            }
        case RANGE_TYPE_NO_LOWER_BOUND:
            switch(parse_range(start_obj_b, end_obj_b))
            {
                case RANGE_TYPE_BOUNDED:
                    /* value_a: (-inf, y), value_b: (z, w) */
                    return false;
                case RANGE_TYPE_NO_LOWER_BOUND:
                    /* value_a: (-inf, y), value_b: (-inf, w) */
                    end_a = json_number_value(end_obj_a);
                    end_b = json_number_value(end_obj_b);
                    return end_a <= end_b;
                case RANGE_TYPE_NO_UPPER_BOUND:
                    /* value_a: (-inf, y), value_b: (z, inf) */
                    return false;
                case RANGE_TYPE_UNBOUNDED:
                    /* value_a: (-inf, y), value_b: (-inf, inf) */
                    return true;
                default:
                    return false;
            }
        case RANGE_TYPE_NO_UPPER_BOUND:
            switch(parse_range(start_obj_b, end_obj_b))
            {
                case RANGE_TYPE_BOUNDED:
                    /* value_a: (x, inf), value_b: (z, w) */
                    return false;
                case RANGE_TYPE_NO_LOWER_BOUND:
                    /* value_a: (x, inf), value_b: (-inf, w) */
                    return false;
                case RANGE_TYPE_NO_UPPER_BOUND:
                    /* value_a: (x, inf), value_b: (z, inf) */
                    start_a = json_number_value(start_obj_a);
                    start_b = json_number_value(start_obj_b);
                    return start_b <= start_a;
                case RANGE_TYPE_UNBOUNDED:
                    /* value_a: (x, inf), value_b: (-inf, inf) */
                    return true;
                default:
                    return false;
            }
        case RANGE_TYPE_UNBOUNDED:
            switch (parse_range(start_obj_b, end_obj_b))
            {
                case RANGE_TYPE_UNBOUNDED:
                    /* value_a: (-inf, inf), value_b: (-inf, inf) */
                    return true;
                default:
                    return false;
            }
        default:
            return false;
    }
}

/* matches values from a with values from b */
bool
match(json_t *value_a, json_t *value_b) {

    VALUE_TYPE type_a = type(value_a);
    VALUE_TYPE type_b = type(value_b);

    /* null matches any value */
    if(type_a == VALUE_TYPE_NULL || type_b == VALUE_TYPE_NULL) {
        write_log(__FILE__, __func__, LOG_DEBUG, "Match: null value");
        return true;
    } 

    switch (type_a)
    {
        case VALUE_TYPE_SINGLE:
            switch (type_b) {
                case VALUE_TYPE_SINGLE:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching single/single.");
                    return match_single_single(value_a, value_b);
                case VALUE_TYPE_SET:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching single/set.");
                    return match_single_set(value_a, value_b);
                case VALUE_TYPE_RANGE:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching single/range.");
                    return match_single_range(value_a, value_b);
                default:
                    return false;
            }
            break;
        case VALUE_TYPE_SET:
            switch (type_b) {
                case VALUE_TYPE_SINGLE:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching set/single.");
                    return match_single_set(value_b, value_a);
                case VALUE_TYPE_SET:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching set/set.");
                    return match_set_set(value_a, value_b);
                case VALUE_TYPE_RANGE:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching set/range.");
                    return match_set_range(value_a, value_b);
                default:
                    return false;
            }
            break;
        case VALUE_TYPE_RANGE:
            switch (type_b) {
                case VALUE_TYPE_SINGLE:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching range/single.");
                    return match_single_range(value_b, value_a);
                case VALUE_TYPE_SET:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching range/set.");
                    return match_set_range(value_b, value_a);
                case VALUE_TYPE_RANGE:
                    write_log(__FILE__, __func__, LOG_DEBUG, "Matching range/range.");
                    return match_range_range(value_a, value_b);
                default:
                    return false;
            }
            break;
    
        default:
            return false;
    }
}

/* check if a is a subset of b, returns 0 if true, 1 if b does not contain all keys in a, 2 if the values of a key does not match */
int
subset(json_t *prop_a, json_t *prop_b)
{
    const char *key_a;
    json_t *value_prop_a;
    json_t *value_prop_b;
    json_t *value_a;
    json_t *value_b;
    int result = 0;

    if(!prop_a) {
        write_log(__FILE__, __func__, LOG_DEBUG, "prop_a == NULL.");
        return 0;
    }

    json_object_foreach(prop_a, key_a, value_prop_a) {
        value_prop_b = json_object_get(prop_b, key_a);

        if (value_prop_b == NULL) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Subset does not contain key \"%s\".", key_a);
            result = 1;
            continue;
        }
        value_b = json_object_get(value_prop_b, "value");
        value_a = json_object_get(value_prop_a, "value");

        //if (!json_equal(value_a, value_b)) {
        if (!match(value_a, value_b)) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Subset check returns false: wrong value for key \"%s\".", key_a);
            return 2;
        }
    }
    write_log(__FILE__, __func__, LOG_DEBUG, "Subset check returns true: this is a subset.");
    return result;
}

bool
update_property(json_t *prop_a, json_t *prop_b)
{
    json_t *value_a = json_object_get(prop_a, "value");
    json_t *value_b = json_object_get(prop_b, "value");

    bool is_match = match(value_a, value_b);
    if(!is_match) {
        write_log(__FILE__, __func__, LOG_DEBUG, "Properties do not match.");
    } else {
        write_log(__FILE__, __func__, LOG_DEBUG, "Match found.");
    }

    json_t *precedence_value_a_obj = json_object_get(prop_a, "precedence");
    int precedence_value_a = precedence_value_a_obj ? json_integer_value(precedence_value_a_obj) : 0;

    json_t *precedence_value_b_obj = json_object_get(prop_b, "precedence");
    int precedence_value_b = precedence_value_b_obj ? json_integer_value(precedence_value_b_obj) : 0;

    if(precedence_value_a == PRECEDENCE_IMMUTABLE && precedence_value_b == PRECEDENCE_IMMUTABLE) {
        if(is_match) {
            return true;
        } else {
            write_log(__FILE__, __func__, LOG_DEBUG, "Immutable property, skipping update.");
            return false;
        }
    }

    if (precedence_value_b >= precedence_value_a && (is_match || precedence_value_a == PRECEDENCE_BASE)) {
        write_log(__FILE__, __func__, LOG_DEBUG, "Updating property.");
        json_t *score_prop_a = json_object_get(prop_a, "score");
        json_t *score_prop_b = json_object_get(prop_b, "score");

        json_int_t score_a = score_prop_a ? json_integer_value(score_prop_a) : 0;
        json_int_t score_b = score_prop_b ? json_integer_value(score_prop_b) : 0;
        
        json_object_set_new(value_a, "score", json_pack("i", score_a + score_b));
        json_object_set(prop_a, "precedence", precedence_value_b_obj);

        VALUE_TYPE type_a = type(value_a);
        VALUE_TYPE type_b = type(value_b);

        switch (type_a)
        {
            case VALUE_TYPE_SINGLE:
                switch (type_b) {
                    case VALUE_TYPE_SINGLE:
                        json_object_set(prop_a, "value", value_b);
                        break;
                    default:
                        break;
                }
                break;
            case VALUE_TYPE_SET:
                switch (type_b) {
                    case VALUE_TYPE_SINGLE:
                        json_object_set(prop_a, "value", value_b);
                        break;
                    default:
                        break;
                }
                break;
            case VALUE_TYPE_RANGE:
                switch (type_b) {
                    case VALUE_TYPE_SINGLE:
                        json_object_set(prop_a, "value", value_b);
                        break;
                    case VALUE_TYPE_SET:
                        json_object_set(prop_a, "value", value_b);
                        break;
                    default:
                        break;;
                }
                break;
            case VALUE_TYPE_NULL:
                json_object_set(prop_a, "value", value_b);
                break;
            default:
                break;
        }
    }
    return true;
}

/* update prop_a with values from prop_b */
bool
merge_do_update_property(json_t *prop_a, json_t *prop_b, bool evaluated)
{
    json_object_set(prop_a, "evaluated", json_pack("b", evaluated));

    json_t *value_a = json_object_get(prop_a, "value");
    json_t *value_b = json_object_get(prop_b, "value");

    if (!value_b) {
        write_log(__FILE__, __func__, LOG_ERROR, "value_b == NULL");
        return false;
    }

    /* null = match all */
    if (value_a == NULL || json_equal(value_a, value_b)) {
        json_t *score_value_a_obj = json_object_get(prop_a, "score");
        int score_value_a = score_value_a_obj ? json_integer_value(score_value_a_obj) : 0;

        json_t *score_value_b_obj = json_object_get(prop_b, "score");
        int score_value_b = score_value_b_obj ? json_integer_value(score_value_b_obj) : 0;

        json_object_set_new(prop_a, "score", json_pack("i", score_value_a + score_value_b));

        json_t *precedence_value_a_obj = json_object_get(prop_a, "precedence");
        int precedence_value_a = precedence_value_a_obj ? json_integer_value(precedence_value_a_obj) : 0;

        json_t *precedence_value_b_obj = json_object_get(prop_b, "precedence");
        int precedence_value_b = precedence_value_b_obj ? json_integer_value(precedence_value_b_obj) : 0;

        json_object_set_new(prop_a, "precedence", json_integer((int)MAX(precedence_value_a, precedence_value_b)));
    }
    else {
        return update_property(prop_a, prop_b);
    }

    return true;
}

/* decide if reverse comparision is to be used */
bool
merge_update_property(json_t *prop_a, json_t *prop_b)
{
    json_t *precedence_prop_b_json = json_object_get(prop_b, "precedence");

    if (!precedence_prop_b_json) {
        write_log(__FILE__, __func__, LOG_DEBUG, "No precedence attribute, adding default value...");
        json_object_set_new(prop_b, "precedence", json_integer(PRECEDENCE_BASE));
    }
    int precedence_prop_b = json_integer_value(precedence_prop_b_json);

    if (precedence_prop_b == PRECEDENCE_BASE) {
        json_t *prop_b_copy = json_deep_copy(prop_b);
        if(!merge_do_update_property(prop_b_copy, prop_a, false))
            return false;
        json_object_update(prop_a, prop_b_copy);
        json_decref(prop_b_copy);
        return true;
    }

    /* merge prop_b into prop_a */
    return merge_do_update_property(prop_a, prop_b, true);
}

/* merge properties in prop_a into prop_b */
bool
merge_properties(json_t *prop_a, json_t *prop_b, int should_overwrite)
{
    const char *key;
    json_t *value;

    json_object_foreach(prop_a, key, value) {
        json_t *found_prop = json_object_get(prop_b, key);
        
        if (!found_prop || should_overwrite) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Inserting new property \"%s\".", key);
            json_object_set(prop_b, key, value);
        }
        else {
            /* Update the property values */
            write_log(__FILE__, __func__, LOG_DEBUG, "Updating property \"%s\".", key);
            if(!merge_update_property(found_prop, value)) {
                return false;
            }
        }
    }
    return true;
}

void 
print_score(int score) {
    char buffer[20];
    char *translated;

    snprintf(buffer, 20, "%.1f", (double) score);
    size_t i, len = strlen(buffer);
    if(len == 0) {
        return;
    }

    if(buffer[0] == '-')
        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s", "₋");
    else
        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s", "₊");

    for(i = 0; i < len; i++) {
        switch(buffer[i])
        {
            case '0':
                translated = "₀";
                break;
            case '1':
                translated = "₁";
                break;
            case '2':
                translated = "₂";
                break;
            case '3':
                translated = "₃";
                break;
            case '4':
                translated = "₄";
                break;
            case '5':
                translated = "₅";
                break;
            case '6':
                translated = "₆";
                break;
            case '7':
                translated = "₇";
                break;
            case '8':
                translated = "₈";
                break;
            case '9':
                translated = "₉";
                break;
            default:
                translated = ".";
                break;
        }
        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s", translated);
    }
}

void print_json_aux(json_t *root) 
{
    const char *key;
    json_t *value;
    size_t i, len;

    if(!root) {
        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "NA");
        return;
    }

    switch (json_typeof(root))
    {
        case JSON_OBJECT:
            if(type(root) == VALUE_TYPE_RANGE) {
                print_json_aux(json_object_get(root, "start"));
                write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "-");
                print_json_aux(json_object_get(root, "end"));
            } else {
                write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "NA");
            }
            break;
        case JSON_ARRAY:;
            len = json_array_size(root) - 1;
            json_array_foreach(root, i, value) {
                print_json_aux(value);
                if(i < len)
                    write_log(__FILE__, __func__, LOG_NO_NEW_LINE, ",");
            }
            break;
        case JSON_STRING:
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s", json_string_value(root));
            break;
        case JSON_INTEGER:
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%lld", json_integer_value(root));
            break;
        case JSON_REAL:
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%.4f", json_real_value(root));
            break;
        case JSON_TRUE:
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "True");
            break;
        case JSON_FALSE:
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "False");
            break;
        default:
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "NA");
            break;
    }
}

void 
do_pretty_print(json_t *candidate, bool should_print_score) {
    json_t *prop;
    const char *key;

    write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s├─%s", LIGHT_GREY, NORMAL);
    json_object_foreach(candidate, key, prop) {
        json_t *value_obj = json_object_get(prop, "value");
        json_t *score_obj = json_object_get(prop, "score");
        json_t *eval_obj = json_object_get(prop, "evaluated");
        json_t *precedence_obj = json_object_get(prop, "precedence");
            
        int score = json_integer_value(score_obj);
        bool evaluated = json_is_true(eval_obj);
        int precedence = json_integer_value(precedence_obj);

        if(strncmp("__", key, 2) == 0)
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, LIGHT_GREY);
        else
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, DARK_GREY);
        if(precedence > 1)
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "[");
        else if(precedence == 1)
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "(");
        if(evaluated)
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, UNDERLINE);

        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s|", key);
        print_json_aux(value_obj);

        if(evaluated)
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, UNDERLINE_END);
        if(precedence > 1)
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "]");
        else if(precedence == 1)
            write_log(__FILE__, __func__, LOG_NO_NEW_LINE, ")");
        if(score > 0)
            print_score(score);

        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s─%s", LIGHT_GREY, NORMAL);
    }
    write_log(__FILE__, __func__, LOG_NO_NEW_LINE, "%s┤%s", LIGHT_GREY, NORMAL);

    if(should_print_score) {
        score_t score_s = property_score_sum(candidate);
        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, " score: %d\n", score_s.evaluated);
    }
    else {
        write_log(__FILE__, __func__, LOG_NEW_LINE, "");
    }
}

/* print properties in a human-readable format */
void pretty_print(json_t *element, bool should_print_score)
{
    size_t i;
    json_t *value;

    if(!element)
        return;

    if(json_is_array(element)) {
        json_array_foreach(element, i, value) {
            do_pretty_print(value, should_print_score);
        }
    } else {
        do_pretty_print(element, should_print_score);
    }
}
