#include <stdlib.h>
//TODO: Remove when proper logging is in place
#include <stdio.h>
#include <uv.h>
#include <assert.h>

#include "neat.h"
#include "neat_core.h"
#include "neat_queue.h"

#ifdef __linux__
    #include "neat_linux_internal.h"
#endif

//Intiailize the OS-independent part of the context, and call the OS-dependent
//init function
uint8_t neat_init_ctx(struct neat_ctx *nc)
{
    nc->loop = malloc(sizeof(uv_loop_t));

    if (nc->loop == NULL)
        return RETVAL_FAILURE;

    uv_loop_init(nc->loop);
    LIST_INIT(&(nc->src_addrs));

#ifdef __linux__
    return neat_linux_init_ctx(nc);
#else
    return RETVAL_FAILURE;
#endif
}

//Start the internal NEAT event loop
//TODO: Add support for embedding libuv loops in other event loops
void neat_start_event_loop(struct neat_ctx *nc)
{
    uv_run(nc->loop, UV_RUN_DEFAULT);
    uv_loop_close(nc->loop);
}

//Free any resource used by the context
//TODO: Consider adding callback, like for resolver
void neat_free_ctx(struct neat_ctx *nc)
{
    if (nc->cleanup)
        nc->cleanup(nc);

    free(nc->loop);
}

//The three functions that deal with the NEAT callback API. Nothing very
//interesting, register a callback, run all callbacks and remove callbacks
uint8_t neat_add_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    uint8_t i = 0;
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr;

    if (event_type > NEAT_MAX_EVENT)
        return RETVAL_FAILURE;

    //Do not initialize callback array before we have to, in case no-one will
    //use the callback API
    if (!nc->event_cbs) {
        nc->event_cbs = calloc(NEAT_MAX_EVENT + 1,
                sizeof(struct neat_event_cbs));

        //TODO: Decide what to do here
        assert(nc->event_cbs != NULL);

        for (i = 0; i < NEAT_MAX_EVENT; i++)
            LIST_INIT(&(nc->event_cbs[i]));
    }

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next) {
  
        if (cb_itr == cb) {
            //TODO: Debug level
            fprintf(stdout, "Callback for %u has already been added\n",
                    event_type); 
            return RETVAL_FAILURE;
        }
    }

    //TODO: Debug level
    fprintf(stdout, "Added new callback for event type %u\n", event_type); 
    LIST_INSERT_HEAD(cb_list_head, cb, next_cb);
    return RETVAL_SUCCESS;
}

uint8_t neat_remove_event_cb(struct neat_ctx *nc, uint8_t event_type,
        struct neat_event_cb *cb)
{
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr = NULL;

    if (event_type > NEAT_MAX_EVENT ||
        !nc->event_cbs)
        return RETVAL_FAILURE;

    cb_list_head = &(nc->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next) {
        if (cb_itr == cb)
            break;
    }

    if (cb_itr) {
        //TODO: Debug level print
        fprintf(stdout, "Removed callback for type %u\n", event_type);
        LIST_REMOVE(cb_itr, next_cb);
    }

    return RETVAL_SUCCESS;
}

void neat_run_event_cb(struct neat_ctx *nc, uint8_t event_type,
        void *data)
{
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr = NULL;

    if (event_type > NEAT_MAX_EVENT ||
        !nc->event_cbs)
        return;

    cb_list_head = &(nc->event_cbs[event_type]);
    
    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next)
        cb_itr->event_cb(nc, cb_itr->data, data);
}
