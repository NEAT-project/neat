#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <jansson.h>
#include <dirent.h>

#include "pm_helper.h"
#include "node.h"

void
free_node(node_t *node) {
    if(node != NULL) {
        free(node->filename);
        json_decref(node->json);
    }
    free(node);
}

void
free_nodes(node_t *head)
{
    node_t  *tmp;

    while (head != NULL) {
       tmp = head;
       head = head->next;
       free_node(tmp);
    }
}

void
update_node_content(node_t *node, json_t *json)
{
    if(json != NULL && node != NULL) {
        if(node->json != NULL) {
            json_decref(node->json);
        }
        node->json = json;
        node->last_updated = time(0);
    }
}

node_t *
node_init(const char *file_path)
{
    node_t *node = calloc(1,sizeof(node_t));

    if(node == NULL) {
        write_log(__FILE__, __func__, LOG_ERROR, "Failed to allocate memory");
        return NULL;
    }

    node->filename = strdup(file_path);
    node->last_updated = 0;
    return node;
}

node_t *
create_node(const char * file_path)
{
    json_t *json = load_json_file(file_path);

    if(json == NULL) { 
        return NULL; 
    }

    node_t* node = node_init(file_path);
    update_node_content(node, json);

    return node;
}


bool
has_node(node_t *head, const char *file_path)
{
    if(file_path == NULL) { return false; }

    node_t *current = head;
    while(current != NULL) {
        if(strcmp(current->filename,file_path) == 0) {
            return true;
        }
        current = current->next;
    }
    return false;
}

node_t *
add_node(node_t *head, node_t *node)
{
    node_t *current;
    json_t *prio_obj;
    json_t *uid_obj;
    json_t *filename_obj;
    int priority;
    int curr_priority;
    const char *uid;

    if(node == NULL) { return head; }
    if(head == NULL) { return node; }

    uid_obj = json_object_get(node->json, "uid");
    uid = json_string_value(uid_obj);
    if(uid_obj) {
        write_log(__FILE__, __func__, LOG_EVENT, "Loading node: %s", uid);
    }
    
    prio_obj = json_object_get(node->json, "priority");
    if (!prio_obj) {
        write_log(__FILE__, __func__, LOG_DEBUG, "No priority property defined");
    }
    priority = json_integer_value(prio_obj);

    /* insert into sorted linked list by priority */
    /* check head first */
    current = head;
    curr_priority = json_integer_value(json_object_get(current->json, "priority"));
    if (priority < curr_priority) {
        node->next = head;
        head = node;
        return head;
    }
    /* and the sandwiched case */
    while(current->next != NULL) {
        int next_priority = json_integer_value(json_object_get(current->next->json, "priority"));
        if (priority < next_priority) {
            break;
        }
        current = current->next;
    }

    node->next  = current->next;
    current->next = node;
    return head;
}

void
remove_node(node_t **head, const char *file_path)
{
    if(head == NULL || file_path == NULL) { return; }

    node_t *current = *head;
    node_t *previous = NULL;

    while(current != NULL) {
        if(strcmp(current->filename,file_path) == 0) {
            write_log(__FILE__, __func__, LOG_DEBUG, "Removing %s", file_path);
            if(previous == NULL) {
                *head = current->next;
            }
            else {
                previous->next = current->next;
            }
            free_node(current);
            remove(file_path);
            return;
        }
        previous = current;
        current = current->next;
    }
}

node_t *
get_node(node_t *head, const char *file_path)
{
    if(file_path == NULL) { return NULL; }

    node_t *current = head;
    while(current != NULL) {
        if(strcmp(current->filename, file_path) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

//testing
void
print_nodes(node_t* head)
{
    node_t *current = head;
    while(current != NULL) {
        print_node(current);
        current= current->next;
    }
}

void
print_node(node_t *node)
{
    if(node != NULL) {
      write_log(__FILE__, __func__, LOG_EVENT, "--------NODE----------\n");
        if(node->filename != NULL) {
             write_log(__FILE__, __func__, LOG_EVENT, "filename: %s\n", node->filename);
        }
        write_log(__FILE__, __func__, LOG_EVENT, "last_updated: %s", ctime(&node->last_updated));
        char *json_string = json_dumps(node->json, JSON_INDENT(4));
        write_log(__FILE__, __func__, LOG_EVENT, "json: %s\n" , json_string);
        free(json_string);
    }
}

/* recursive sort */
node_t *
sort_nodes(node_t *head)
{
    if(head->next) {
        sort_nodes(head->next);

        int curr_priority = json_integer_value(json_object_get(head->json, "priority"));
        int next_priority = json_integer_value(json_object_get(head->next->json, "priority"));

        if(curr_priority > next_priority) {
            node_t *tmp = head->next;
            head->next = head->next->next;
            tmp->next = head;
            head = tmp;
        }
    }
    return head;
}

node_t *
update_node(node_t *head, char *file_path)
{
    node_t *node;
    json_t *json = load_json_file(file_path);
    if(!json) {
        return head;
    }

    json_t *uid_obj = json_object_get(json, "uid");
    const char *uid = json_string_value(uid_obj);

    if(!uid_obj) {
        write_log(__FILE__, __func__, LOG_DEBUG, "Skipping node: %s: uid not found", file_path);
        return head;
    }
    /* Is there already a node with the same uid? */
    if(node = get_node_by_uid(head, uid)) {
        if(node->last_updated <= file_edit_time(file_path)) {
            write_log(__FILE__, __func__, LOG_EVENT, "Updating node: %s", uid);
            update_node_content(node, json);
            return sort_nodes(head);
        }
        json_decref(json);
        return head;
    } 

    /* Else, create a new node */
    json_decref(json);
    return add_node(head, create_node(file_path));
}

node_t *
read_modified_files(node_t *head, const char *dir_path)
{
    DIR *dir;
    struct dirent *ent;
    int file_type = 8;

    if ((dir = opendir (dir_path)) != NULL) {
        while ((ent = readdir (dir)) != NULL) {
            if (ent->d_type == file_type) {
                char *file_path = new_string("%s%s", dir_path, ent->d_name);
                head = update_node(head, file_path);
                free(file_path);
            }
        }
        closedir (dir);
        return head;
    } else {
        write_log(__FILE__, __func__, LOG_ERROR, "Can't read the directory %s", dir_path);
    }
    return NULL;
}

json_t *
get_node_properties(node_t *node)
{
    if(node != NULL) {
        return json_object_get(node->json, "properties");
    }
    return NULL;
}

json_t *
node_has_property(node_t *node, const char *prop)
{
    return json_object_get(get_node_properties(node), prop);
}

void
node_set_property(node_t *node, const char *prop, json_t *new_value)
{
    if(json_object_set(get_node_properties(node), prop, new_value) == -1) {
        write_log(__FILE__,__func__, LOG_ERROR, "Unable to update property %s", prop);
    }
}

node_t *
get_node_by_uid(node_t *head, const char *uid)
{
    const char *current_uid;

    node_t *current = head;
    while(current != NULL) {
        current_uid = json_string_value(json_object_get(current->json, "uid"));
        if(strcmp(current_uid, uid) == 0) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}
