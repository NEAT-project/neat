#ifndef NEAT_STAT_H
#define NEAT_STAT_H

#include <stdint.h>
#include <string.h>
#include <jansson.h>

void neat_stats_build_json(char **json_stats);

// Struct for collecting global statistics
struct neat_stat{
  uint32_t num_flows; // Number of active flows
	
  /* List of active flows This, I would presume belongs somewhere else*/
  // Remember to clean when a flow ends, cleanly or in other ways
  // Figure out whether to keep references to key data structures like 
  // a flow list here or in other central neat data structures.  
};


#endif
