#ifndef NEAT_STAT_H
#define NEAT_STAT_H

#include <stdint.h>
#include <string.h>
#include <jansson.h>
#include "neat_internal.h"

void neat_stats_build_json(struct neat_ctx *ctx, char **json_stats);

/*Struct for collecting global statistics*/
struct neat_stat{
  uint32_t num_flows;

  /* List of active flows. This should maybe be kept somewhere else ?*/

  /* This is a data structure to keep global stats and pointers for
     collecting stats if we want to implement this instead of per-flow
     stats only.Gathering statistics periodically might be useful 
     for the policy manager? Use a timed callback for this? */ 
};

typedef struct neat_stat neat_stat;

#endif
