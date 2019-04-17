#ifndef HEADER_MODIFIED_FILE
#define HEADER_MODIFIED_FILE

#include <stdbool.h>
#include <time.h>
#include <jansson.h>

#include "pm_helper.h"

typedef struct node {
    char *filename;
    time_t last_updated;
    json_t *json;
    struct node *next;
}node_t;

node_t* node_init(const char *file_path);
void free_node(node_t *node);
void free_nodes(node_t *head);

node_t* create_node(const char * file_path);
void update_node_content(node_t *node, json_t *json);
node_t* read_modified_files(node_t *head, const char *dir);

bool has_node(node_t *head, const char *file_path);
node_t* add_node(node_t *head, node_t *node);
void remove_node(node_t **head, const char *file_path);
node_t* get_node(node_t *head, const char *file_path);

json_t* get_node_properties(node_t *node);
json_t* node_has_property(node_t *node, const char *prop);
void node_set_property(node_t *node, const char *prop, json_t *new_value);

void print_nodes(node_t* head);
void print_node(node_t *node);

//int subset(json_t *prop_a, json_t *prop_b);
//bool merge_properties(json_t *prop_a, json_t *prop_b, int should_overwrite);

node_t *get_node_by_uid (node_t *head, const char *uid);
node_t *update_node(node_t *head, char *file_path);

#endif
