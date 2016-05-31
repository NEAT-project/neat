#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "neat_core.h"
#include "neat_stat.h"


/* Traverse the relevant susystems of NEAT and gather the stats
   then format the stats as a json string to return */	
void neat_stats_build_json(char *json_stats, uint32_t *stats_len){

// dummy data for json representation until data gathering logic is in place
 // int num_flows, flow1bytes, flow2bytes;
  
  //num_flows = 2;
  //flow1bytes = 1872614;
  //flow2bytes = 7423468;

  json_t *root = json_object();
  
  json_object_set_new( root, "flowID", json_integer( 1 ) );


} 



