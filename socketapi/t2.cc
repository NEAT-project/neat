#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/queue.h>


struct event_signal_node
{
   TAILQ_ENTRY(event_signal_node) esn_node;
   int num;
};

 struct event_signal
{
   bool            es_has_fired;
   TAILQ_HEAD(slisthead, event_signal_node) es_parent_list;
};


int main(int argc, char** argv)
{
   event_signal es;
   TAILQ_INIT(&es.es_parent_list);

   struct event_signal_node* n1 = (struct event_signal_node*)malloc(sizeof(struct event_signal_node));
   n1->num=1;
   TAILQ_INSERT_TAIL(&es.es_parent_list, n1, esn_node);

   struct event_signal_node* n2 = (struct event_signal_node*)malloc(sizeof(struct event_signal_node));
   n2->num=2;
   TAILQ_INSERT_TAIL(&es.es_parent_list, n2, esn_node);

   struct event_signal_node* n3 = (struct event_signal_node*)malloc(sizeof(struct event_signal_node));
   n3->num=3;
   TAILQ_INSERT_TAIL(&es.es_parent_list, n3, esn_node);


   struct event_signal_node* np;
   TAILQ_FOREACH(np, &es.es_parent_list, esn_node) {
      printf("N=%d\n", np->num);
   }

   while( (np = TAILQ_FIRST(&es.es_parent_list)) != NULL ) {
      TAILQ_REMOVE(&es.es_parent_list, np, esn_node);
      free(np);
   }

   return 0;
}
