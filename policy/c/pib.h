#ifndef HEADER_PIB
#define HEADER_PIB

#include "node.h"

extern node_t *pib_policies;
extern node_t *pib_profiles;

void add_pib_node(json_t *json_for_node);
void remove_pib_node(const char *uid);
json_t *get_pib_list();
json_t *profile_lookup(json_t *);
json_t *policy_lookup(json_t *);
void pib_start();
void pib_close();
json_t *get_pibnode_by_uid (const char *uid);

#endif
