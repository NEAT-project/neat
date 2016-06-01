#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "neat_core.h"
#include "neat_stat.h"


/* Traverse the relevant susystems of NEAT and gather the stats
   then format the stats as a json string to return */	
void neat_stats_build_json(char **json_stats){

// Using  dummy data for json representation until data gathering logic is in place

  json_t *root = json_object();
  
  json_object_set_new( root, "numFlows", json_integer( 2 ) );
  json_object_set_new( root, "neatBytesSent", json_integer( 94561245 ) );
  json_object_set_new( root, "neatBytesReceived", json_integer( 62346723 ) );
  json_object_set_new( root, "neatPacketsSent", json_integer( 263040 ) );
  json_object_set_new( root, "numFlows", json_integer( 2 ) );

  json_t *flow1 = json_object();
  json_object_set_new( root, "flow1", flow1 );
  json_object_set_new( flow1, "bytesSent", json_integer( 45664 ) );
  json_object_set_new( flow1, "bytesReceived", json_integer( 6573 ) );

  json_t *flow2 = json_object();
  json_object_set_new( root, "flow2", flow2 );
  json_object_set_new( flow2, "bytesSent", json_integer( 13664 ) );
  json_object_set_new( flow2, "bytesReceived", json_integer( 521 ) );

  /* Callers must remember to free the output */
 
  *json_stats = json_dumps(root, 0);

  json_decref(root);
  
  return;
} 



