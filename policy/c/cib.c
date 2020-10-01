#define _GNU_SOURCE

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <netdb.h>
#include <jansson.h>

#include "cib.h"
#include "pm_helper.h"
#include "node.h"
#include "parse_json.h"

node_t *cib_nodes = NULL;
json_t *cib_rows = NULL;

void
remove_cib_node(const char *uid) 
{
    char *path = new_string("%s%s.cib", cib_dir, uid);
    remove_node(&cib_nodes, path);

    json_decref(cib_rows);
    cib_rows = update_rows();

    free(path);
    return;
}

bool
node_is_expired(node_t *node) {
    json_t *node_expire = json_object_get(node->json, "expire");

    if(json_is_number(node_expire)) {
        double expire = json_number_value(node_expire);
        if(expire > 0) {
            struct timespec spec;
            clock_gettime(CLOCK_REALTIME, &spec);

            if(expire - spec.tv_sec <= 0) {
                return true;
            }
        }
    }

    return false;
}

bool
node_is_cached(json_t *node_json) {
    json_t *cached = json_object_get(json_object_get(node_json, "properties"), "__cached");
    if (cached){

        return true;
    }
    return false;
}

void
extend_property(json_t *properties, node_t *extension_node, json_t *uid) 
{
    json_t *extension_props = expand_json(json_object_get(extension_node->json, "properties"));
    json_t *extension_prop;
    json_t *match_array = expand_json(json_object_get(extension_node->json, "match"));
    json_t *match_obj;
    json_t *match_uid;
    size_t i, j;

    if(!match_array || json_array_size(match_array) == 0) {
        json_array_foreach(extension_props, j, extension_prop) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Extending property. (match any)");
            merge_properties(extension_prop, properties, 1);
        }
    } else {
        json_array_foreach(match_array, i, match_obj) {
            match_uid = json_object_get(match_obj, "uid");
            if (subset(match_obj, properties) == 0 || \
                json_equal(uid, json_object_get(json_object_get(match_obj, "uid"), "value"))) {
                json_array_foreach(extension_props, j, extension_prop) {
                    write_log(__FILE__, __func__, LOG_DEBUG, "Extending property.");
                    merge_properties(extension_prop, properties, 1);
                }
                break;
            }
        }
    }

    json_decref(extension_props);
    json_decref(match_array);
}

void
extend_node_aux(json_t *input_prop, node_t *extension_node, json_t *uid)
{
    json_t *value_a; // Element of outer array (if it exists)
    json_t *value_b; // Element of inner array (if it exists)

    size_t i, j;

    if(json_is_array(input_prop)) {
        json_array_foreach(input_prop, i, value_a) {
            // Case: input is 2D array
            if(json_is_array(value_a)) {
                json_array_foreach(value_a, j, value_b) {
                    extend_property(value_b, extension_node, uid);
                }
            // Case: input is 1D array
            } else if(json_is_object(value_a)) {
                extend_property(value_a, extension_node, uid);
            }
        }
    // Case: input is object */
    } else if(json_is_object(input_prop)) {
        extend_property(input_prop, extension_node, uid);
    }
}

/* Extends CIB node */
json_t *
extend_node(json_t *input_json)
{
    node_t *current_node = NULL;
    json_t *uid = json_object_get(input_json, "uid");
    json_t *result = json_array();

    for(current_node = cib_nodes; current_node; current_node = current_node->next) {
        // Discard expired entries
        if(node_is_expired(current_node)) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Discarding expired entry.");
            continue;
        }
        // Ignore cached nodes if caching disabled
        if(!cib_cache_enabled && node_is_cached(current_node->json)) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Ignoring cached node.");
            continue;
        }
        // Do not expand from root nodes
        if(json_boolean_value(json_object_get(current_node->json, "root"))) {
            continue;
        } else {
            write_log(__FILE__, __func__, LOG_DEBUG,"---------- EXTENDER %s ---------", current_node->filename);
            bool link = json_boolean_value(json_object_get(current_node->json, "link"));
            // If node
            if(link) {
                write_log(__FILE__, __func__, LOG_DEBUG, "Extending node.");
                json_t *input_prop = json_object_get(input_json, "properties");
                json_t *new_prop = json_deep_copy(input_prop);

                extend_node_aux(new_prop, current_node, uid);
                if (json_equal(input_prop, new_prop)) {
                    json_decref(new_prop);
                    continue;
                }
                json_array_append_new(result, new_prop); 
            }
        }
    }

    return result;
}

/* Extends CIB row */
void *
extend_row(json_t *input_json)
{
    node_t *current_node = NULL;
    json_t *uid = json_object_get(input_json, "uid");
    //json_t *result = json_array();

    for(current_node = cib_nodes; current_node; current_node = current_node->next) {
        // Discard expired entries
        if(node_is_expired(current_node)) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Discarding expired entry.");
            continue;
        }
        // Ignore cached nodes if caching disabled
        if(!cib_cache_enabled && node_is_cached(current_node->json)) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Ignoring cached node.");
            continue;
        }
        // Do not expand from root nodes
        if(json_boolean_value(json_object_get(current_node->json, "root"))) {
            continue;
        } else {
            write_log(__FILE__, __func__, LOG_DEBUG,"---------- EXTENDER %s ---------", current_node->filename);
            bool link = json_boolean_value(json_object_get(current_node->json, "link"));
            // If row  
            if(!link) {
                write_log(__FILE__, __func__, LOG_DEBUG, "Extending row.");
                extend_node_aux(input_json, current_node, uid);
            }
        }
    }
}

json_t *
update_rows()
{
    node_t *current_node = NULL;
    json_t *rows = json_array();
    json_t *row;

    json_t *value_a, *value_b;
    size_t i, j;

    for(current_node = cib_nodes; current_node; current_node = current_node->next) {
        write_log(__FILE__, __func__, LOG_DEBUG,"---------- NODE %s ---------", current_node->filename);
        // Discard expired entries
        if(node_is_expired(current_node)) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Discarding expired entry.");
            continue;
        }
        // Ignore cached nodes if caching disabled
        if(!cib_cache_enabled && node_is_cached(current_node->json)) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Ignoring cached node.");
            continue;
        }
        if(!json_boolean_value(json_object_get(current_node->json, "root"))) {
            continue;
        }
        // Extend current node
        write_log(__FILE__, __func__, LOG_DEBUG,"---------- EXTENDING NODE ---------");
        json_t *prop_array = extend_node(current_node->json);

        // If no matching extender 
        if (json_array_size(prop_array) == 0) {
            json_array_append(prop_array, json_object_get(current_node->json, "properties"));
        }
        
        json_array_foreach(prop_array, i, value_a) {
            row = expand_json(value_a);

            if(json_array_size(row) == 0) {
                json_decref(row);
                break;
            }
            json_array_append(rows, row);

            write_log(__FILE__, __func__, LOG_DEBUG,"---------- EXTENDING ROW ---------");

            extend_row(row);
            json_array_append_new(rows, row);
        }

        json_decref(prop_array);
    }

    return rows;
}

json_t *
get_rows() {
    return cib_rows;
}

void
get_cib_list_aux(json_t *cib_array, node_t *head)
{
    if(head != NULL) {
        json_array_append(cib_array, json_object_get(head->json, "uid"));
        get_cib_list_aux(cib_array, head->next);
    }
}

json_t *
get_cib_list()
{
    json_t *cib_array = json_array();
    get_cib_list_aux(cib_array, cib_nodes);
    return cib_array;
}

json_t *
get_cibnode_by_uid(const char *uid)
{
    node_t *cib;
    cib = get_node_by_uid(cib_nodes, uid);
    if (cib) {
        return cib->json;
    }
    return NULL;
}

void
add_cib_node(json_t *json_for_node)
{
    if(!json_for_node) {
        return;
    }
    if(!cib_cache_enabled && node_is_cached(json_for_node)) {
        write_log(__FILE__, __func__, LOG_DEBUG, "Ignoring CIB node caching");
        return;
    }

    const char *uid = json_string_value(json_object_get(json_for_node, "uid"));
    char *filename;
    if(uid){
        filename = new_string("%s.cib", uid);
    } else {
        char *new_uid = get_hash();
        json_object_set_new(json_for_node, "uid", json_string(new_uid));
        filename = new_string("%s.cib", new_uid);
        free(new_uid);
    }

    json_object_set_new(json_for_node, "filename", json_string(filename));

    if(json_object_get(json_for_node, "description") == NULL){
        json_object_set_new(json_for_node, "description", json_string(""));
    }
    if(json_object_get(json_for_node, "priority") == NULL){
        json_object_set_new(json_for_node, "priority", json_integer(0));
    }
    if(json_object_get(json_for_node, "root") == NULL){
        json_object_set_new(json_for_node, "root", json_boolean(false));
    }
    if(json_object_get(json_for_node, "expire") == NULL){
        double expiry = time(NULL) + CIB_DEFAULT_TIMEOUT;
        json_object_set_new(json_for_node, "expire", json_real(expiry));
    }

    char *path = new_string("%s%s", cib_dir, filename);
    write_json_file(path, json_for_node);
    
    write_log(__FILE__, __func__, LOG_DEBUG, "Writing node to %s", path);
    update_node(cib_nodes, path);

    json_decref(cib_rows);
    cib_rows = update_rows();

    free(path);
    free(filename);
}

void
generate_cib_from_ifaces()
{
    write_log(__FILE__, __func__, LOG_EVENT, "Generate CIB from interfaces:");

    struct ifaddrs *ifaddr, *interface;
    struct if_nameindex *if_nidxs, *iface;
    int family, s, n;
    char address[NI_MAXHOST];
    void *iter;

    json_t *root = json_object();

    if ((if_nidxs = if_nameindex()) == NULL )
    {
        write_log(__FILE__, __func__, LOG_ERROR, "if_nameindex() failed");
    }
    if (getifaddrs(&ifaddr) == -1) {
        write_log(__FILE__, __func__, LOG_ERROR, "getifaddrs() failed");
    }
    for (iface = if_nidxs; iface->if_index != 0 || iface->if_name != NULL; iface++)
    {
        char* desc = new_string("%s%s", "autogenerated CIB node for local interface ", iface->if_name);
        char* filename = new_string("%s%s", iface->if_name, ".cib");

        json_object_set_new(root, iface->if_name, json_object());
        json_object_set_new(json_object_get(root, iface->if_name), "description", json_string(desc));
        json_object_set_new(json_object_get(root, iface->if_name), "filename", json_string(filename));
        json_object_set_new(json_object_get(root, iface->if_name), "expire", json_integer(-1.0));
        json_object_set_new(json_object_get(root, iface->if_name), "link", json_boolean(false));
        json_object_set_new(json_object_get(root, iface->if_name), "priority", json_integer(0));
        json_object_set_new(json_object_get(root, iface->if_name), "properties", json_array());
        json_array_append_new(json_object_get(json_object_get(root, iface->if_name), "properties"), json_array());
        json_array_append_new(json_object_get(json_object_get(root, iface->if_name), "properties"), json_array());

        json_t *interface_array = json_array_get(json_object_get(json_object_get(root, iface->if_name), "properties"), 0);
        json_array_append_new(interface_array, json_object());

        json_object_set_new(json_array_get(interface_array, 0), "interface", json_object());
        json_object_set_new(json_object_get(json_array_get(interface_array, 0), "interface"), "precedence", json_integer(2));
        json_object_set_new(json_object_get(json_array_get(interface_array, 0), "interface"), "value", json_string(iface->if_name));
        json_object_set_new(json_array_get(interface_array, 0), "local_interface", json_object());
        json_object_set_new(json_object_get(json_array_get(interface_array, 0), "local_interface"), "precedence", json_integer(2));
        json_object_set_new(json_object_get(json_array_get(interface_array, 0), "local_interface"), "value", json_boolean(true));

        free(filename); free(desc);
    }

    for (interface = ifaddr, n = 0; interface != NULL; interface = interface->ifa_next, n++) {
        if (interface->ifa_addr == NULL || interface->ifa_addr->sa_family == AF_PACKET)
            continue;

        family = interface->ifa_addr->sa_family;

        s = getnameinfo(interface->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                            sizeof(struct sockaddr_in6),
                    address, NI_MAXHOST,
                    NULL, 0, NI_NUMERICHOST);
        if (s != 0) {
            write_log(__FILE__, __func__, LOG_ERROR, "getnameinfo() failed: %s", gai_strerror(s));
        }

        iter = json_object_iter(root);
        while(iter){
            if(strcmp(json_object_iter_key(iter), interface->ifa_name) == 0){
                json_t *ip_array = json_array_get(json_object_get(json_object_get(root, interface->ifa_name), "properties"), 1);

                if(family == AF_INET){
                    json_array_append_new(ip_array, json_object());
                    json_object_set_new(json_array_get(ip_array, 0), "ip_version", json_object());
                    json_object_set_new(json_object_get(json_array_get(ip_array, 0), "ip_version"), "precedence", json_integer(2));
                    json_object_set_new(json_object_get(json_array_get(ip_array, 0), "ip_version"), "value", json_integer(4));
                    json_object_set_new(json_array_get(ip_array, 0), "local_ip", json_object());
                    json_object_set_new(json_object_get(json_array_get(ip_array, 0), "local_ip"), "precedence", json_integer(2));
                    json_object_set_new(json_object_get(json_array_get(ip_array, 0), "local_ip"), "value", json_string(address));
                } else if (family == AF_INET6){
                    json_array_append_new(ip_array, json_object());
                    json_object_set_new(json_array_get(ip_array, 1), "ip_version", json_object());
                    json_object_set_new(json_object_get(json_array_get(ip_array, 1), "ip_version"), "precedence", json_integer(2));
                    json_object_set_new(json_object_get(json_array_get(ip_array, 1), "ip_version"), "value", json_integer(6));
                    json_object_set_new(json_array_get(ip_array, 1), "local_ip", json_object());
                    json_object_set_new(json_object_get(json_array_get(ip_array, 1), "local_ip"), "precedence", json_integer(2));
                    json_object_set_new(json_object_get(json_array_get(ip_array, 1), "local_ip"), "value", json_string(address));
                }
            }
            iter = json_object_iter_next(root, iter);
        }
    }

    iter = json_object_iter(root);
    while(iter){
        json_object_set_new(json_object_get(root, json_object_iter_key(iter)), "root", json_boolean(true));
        json_object_set_new(json_object_get(root, json_object_iter_key(iter)), "uid", json_string(json_object_iter_key(iter)));

        char* path = new_string("%s%s%s", cib_dir, json_object_iter_key(iter), ".cib");
        write_json_file(path, json_object_get(root, json_object_iter_key(iter)));
        write_log(__FILE__, __func__, LOG_EVENT, "%s", path);
        free(path);

        iter = json_object_iter_next(root, iter);
    }
    write_log(__FILE__, __func__, LOG_NEW_LINE, "\n");

    freeifaddrs(ifaddr);
    freeifaddrs(interface);
    if_freenameindex(if_nidxs);
    json_decref(root);
}

json_t *
cib_lookup(json_t *input_props)
{
    json_t *candidate_array = json_array();
    json_t *candidate;
    json_t *row;
    json_t *prop;

    size_t i, j;
    bool match = false;

    //json_array_append(candidate_array, input_props);

    json_array_foreach(cib_rows, i, row) {
        json_array_foreach(row, j, prop) {
            write_log(__FILE__, __func__, LOG_DEBUG,"---------- PROCESSING ROW (%d,%d) ---------", i, j);
            candidate = json_deep_copy(input_props);
            
            if(merge_properties(prop, candidate, 0))
            {
                write_log(__FILE__, __func__, LOG_DEBUG,"New candidate added.");
                json_array_append_new(candidate_array, candidate);
                match = true;
            } else {
                write_log(__FILE__, __func__, LOG_DEBUG,"Discarding candidate.");
                json_decref(candidate);
            }
        }
    }
    if(!match) {
        // Only retain old candidate if lookup was not successful
        json_array_append(candidate_array, input_props);
    }

    return candidate_array;
}

void
cib_start()
{
    cib_nodes = read_modified_files(cib_nodes, cib_dir);
    cib_rows = update_rows();
}

void
cib_close()
{
    json_decref(cib_rows);
    free_nodes(cib_nodes);
}
