#include <stdio.h>
#include <jansson.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "pib.h"
#include "node.h"
#include "pm_helper.h"

#include "parse_json.h"
#include "func.h"

node_t *pib_profiles = NULL;
node_t *pib_policies = NULL;

void
get_pib_list_aux (json_t *pib_array, node_t *head)
{
    if(head != NULL) {
        json_array_append(pib_array, json_object_get(head->json, "uid"));
        get_pib_list_aux(pib_array, head->next);
    }
}

json_t *
get_pib_list ()
{
    json_t *pib_array = json_array();
    get_pib_list_aux(pib_array, pib_policies);
    get_pib_list_aux(pib_array, pib_profiles);

    return pib_array;
}

node_t *
get_policy_by_uid(const char *uid)
{
    node_t *pib;
    pib = get_node_by_uid(pib_policies, uid);
    if (pib) {
        return pib;
    }
    return NULL;
}

node_t *
get_profile_by_uid(const char *uid)
{
    node_t *pib;
    pib = get_node_by_uid(pib_profiles, uid);
    if (pib) {
        return pib;
    }
    return NULL;
}

json_t *
get_pibnode_by_uid(const char *uid)
{
    node_t *pib;
    if (pib = get_policy_by_uid(uid)) {
        return pib->json;
    } else if (pib = get_profile_by_uid(uid)) {
        return pib->json;
    }
    return NULL;
}

node_t *
put_pib_node(node_t *head, json_t *json_for_node, char *path, const char *uid) 
{
    char *filename = new_string("%s.policy", uid);
    json_object_set_new(json_for_node, "filename", json_string(filename));


    if(json_object_get(json_for_node, "time") == NULL){
        json_object_set_new(json_for_node, "time", json_integer((int)time(NULL)));
    }

    write_json_file(path, json_for_node);
    head = update_node(head, path);

    write_log(__FILE__, __func__, LOG_DEBUG, "PIB node created in %s\n", path);

    free(filename);
    return head;
}

void
add_pib_node(json_t *json_for_node)
{
    if(!json_for_node) {
        return;
    }
    //Check uid, filename, time
    char *path;
    const char *uid = json_string_value(json_object_get(json_for_node, "uid"));
    const char *type = json_string_value(json_object_get(json_for_node, "policy_type"));
    if(uid == NULL){
        char * new_uid = get_hash();
        json_object_set_new(json_for_node, "uid", json_string(uid));
        uid = json_string_value(json_object_get(json_for_node, "uid"));
        free(new_uid);
    }

    // Make sure there is inly ony policy/profile with the same UID
    if(type && !strncmp(type, "profile", 7)) {
        write_log(__FILE__, __func__, LOG_EVENT, "Inserting %s as profile", uid);
        if(get_policy_by_uid(uid)) {
            path = new_string("%s%s.policy", policy_dir, uid);
            write_log(__FILE__, __func__, LOG_DEBUG, "overwriting policy %s", uid);
            remove_node(&pib_policies, path); // Policy with the same UID is removed
            free(path);
        }
        path = new_string("%s%s.profile", profile_dir, uid);
        pib_profiles = put_pib_node(pib_profiles, json_for_node, path, uid);
        free(path);
    } else {
        write_log(__FILE__, __func__, LOG_EVENT, "Inserting %s as policy", uid);
        if(get_profile_by_uid(uid)) {
            path = new_string("%s%s.profile", profile_dir, uid);
            write_log(__FILE__, __func__, LOG_DEBUG, "overwriting profile %s", uid);
            remove_node(&pib_profiles, path); // Profile with the same UID is removed
            free(path);
        }
        path = new_string("%s%s.policy", policy_dir, uid);
        pib_policies = put_pib_node(pib_policies, json_for_node, path, uid);
        free(path);
    }
}

void
remove_pib_node(const char *uid) 
{
    if(get_policy_by_uid(uid)) {
        char *path = new_string("%s%s.policy", policy_dir, uid);
        remove_node(&pib_policies, path);
        free(path);
    } else {
        char *path = new_string("%s%s.profile", profile_dir, uid);
        remove_node(&pib_profiles, path);
        free(path);
    }
    return;
}

int
replace_matched(json_t *policy)
{
    json_t *replace_matched = json_object_get(policy, "replace_matched");
    if (replace_matched) {
        return json_is_true(replace_matched);
    }
    return 0; /* TODO what is the default value? */
}

json_t *
pib_lookup(node_t *pib_list, json_t *input_props)
{
    node_t *current_policy  = NULL;
    json_t *candidate_array = json_array();
    json_t *candidate_updated_array = json_array();
    json_t *policy_match;

    /* expand */
    json_t *properties_expanded;
    json_t *expanded_prop;
    json_t *candidate_updated;
    size_t index_2;
    int replace;

    /* array variables */
    size_t index;
    json_t *candidate;

    json_array_append(candidate_array, input_props);

    json_array_foreach(candidate_array, index, candidate) {
        candidate_updated = json_deep_copy(candidate);
        
        for (current_policy = pib_list; current_policy; current_policy = current_policy->next) {
            write_log(__FILE__, __func__, LOG_DEBUG,"---------- POLICY %s ---------", current_policy->filename);
            policy_match = json_object_get(current_policy->json, "match");

            /* no match field becomes a match by default */
            if (!policy_match || subset(policy_match, candidate_updated) == 0) {
                write_log(__FILE__, __func__, LOG_DEBUG, "Subset found for %s", current_policy->filename);
                if(verbose) {
                    const char *uid = json_string_value(json_object_get(current_policy->json, "uid"));
                    const char *description = json_string_value(json_object_get(current_policy->json, "description"));
                    if(description) { write_log(__FILE__, __func__, LOG_EVENT, "    %s %s(%s)%s", uid, DARK_GREY, description, NORMAL); }
                    else { write_log(__FILE__, __func__, LOG_EVENT, "    %s", uid); }
                }

                properties_expanded = expand_json(json_object_get(current_policy->json, "properties"));
                replace = replace_matched(current_policy->json);

                json_array_foreach(properties_expanded, index_2, expanded_prop) {
                    write_log(__FILE__, __func__, LOG_DEBUG, "    ------ EXPANDED PROP #%ld of %s", index_2, current_policy->filename);
                    evaluate_funcs(expanded_prop);

                    /* add merged copy to updated array */
                    if(merge_properties(expanded_prop, candidate_updated, replace)) {
                        write_log(__FILE__, __func__, LOG_DEBUG,"New candidate added.");
                    } else {
                        write_log(__FILE__, __func__, LOG_DEBUG, "Discarding candidate.");
                        json_decref(candidate_updated);
                        candidate_updated = NULL;
                        break;
                    }
                }
                json_decref(properties_expanded);
            }
            else {
                write_log(__FILE__, __func__, LOG_DEBUG, "Subset not found for %s\n", current_policy->filename);
            }
        }
        if(candidate_updated) {
            evaluate_funcs(candidate_updated);
            json_array_append_new(candidate_updated_array, candidate_updated);
        }
    }
    json_decref(candidate_array);

    return candidate_updated_array;
}

json_t *
policy_lookup(json_t *input_props)
{
    return pib_lookup(pib_policies, input_props);
}

json_t *
profile_lookup(json_t *input_props)
{
    return pib_lookup(pib_profiles, input_props);
}

void
pib_start()
{
    pib_profiles = read_modified_files(pib_profiles, profile_dir);
    pib_policies = read_modified_files(pib_policies, policy_dir);
}

void
pib_close()
{
    free_nodes(pib_profiles);
    free_nodes(pib_policies);
}
