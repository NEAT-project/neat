#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "neat_internal.h"
#include "neat_core.h"
#include "neat_stat.h"


/* Traverse the relevant susystems of NEAT and gather the stats
   then format the stats as a json string to return */	
void neat_stats_build_json(neat_flow *flow, char **json_stats){

	json_t *root = json_object();

	json_object_set_new( root, "remote_host", json_string( flow->name ));
	json_object_set_new( root, "sock_type", json_integer( flow->sockType ));
	json_object_set_new( root, "sock_protocol", json_integer( flow->sockProtocol ));
	json_object_set_new( root, "port", json_integer( flow->port ));
	

	/* TODO: fetch OS-specific stats from the respective stacks used for connecting */

	/* Callers must remember to free the output */
	*json_stats = json_dumps(root, 0);

	json_decref(root);

	return;
} 



