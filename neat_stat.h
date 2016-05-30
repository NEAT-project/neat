#ifndef NEAT_STAT_H
#define NEAT_STAT_H

#include <stdint.h>

// Struct for collecting global statistics
struct neat_stat{
  uint32_t num_flows; // Number of active flows
	
  /* List of active flows This, I would presume belongs somewhere else*/
  //Remember to clean when a flow ends, cleanly or in other ways
  
};


#endif
