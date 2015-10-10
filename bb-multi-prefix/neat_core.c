#include <stdlib.h>
//TODO: Remove when proper logging is in place
#include <stdio.h>
#include <uv.h>
#include <assert.h>

#include "include/queue.h"
#include "neat.h"
#include "neat_core.h"

#ifdef LINUX
    #include "neat_linux.h"
#endif

struct neat_ctx *neat_alloc_ctx()
{
    struct neat_internal_ctx *nc = NULL;

#ifdef LINUX
    nc = (struct neat_internal_ctx*) neat_alloc_ctx_linux();
#endif

    if (nc == NULL)
        return NULL;

    nc->loop = malloc(sizeof(uv_loop_t));

    if (nc->loop == NULL) {
        free(nc);
        return NULL;
    }

    uv_loop_init(nc->loop);
    LIST_INIT(&(nc->src_addrs));
    return (struct neat_ctx*) nc;
}

uint8_t neat_init_ctx(struct neat_ctx *nc)
{
    struct neat_internal_ctx *nic = (struct neat_internal_ctx*) nc;

    return nic->init(nic);
}

void neat_start_event_loop(struct neat_ctx *nc)
{
    uv_run(nc->loop, UV_RUN_DEFAULT);
    uv_loop_close(nc->loop);
}

void neat_free_ctx(struct neat_ctx *nc)
{
    struct neat_internal_ctx *nic = (struct neat_internal_ctx*) nc;

    if (nic->cleanup)
        nic->cleanup(nic);

    free(nic->loop);
    free(nic);
}

uint8_t neat_add_event_cb(struct neat_internal_ctx *nic, uint8_t event_type,
        struct neat_event_cb *cb)
{
    uint8_t i = 0;
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr;

    if (event_type > NEAT_MAX_EVENT)
        return RETVAL_FAILURE;

    //Do not initialize callback array before we have to
    if (!nic->event_cbs) {
        nic->event_cbs = calloc(NEAT_MAX_EVENT + 1,
                sizeof(struct neat_event_cbs));

        //TODO: Decide what to do here
        assert(nic->event_cbs != NULL);

        for (i = 0; i < NEAT_MAX_EVENT; i++)
            LIST_INIT(&(nic->event_cbs[i]));
    }

    cb_list_head = &(nic->event_cbs[event_type]);

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

void neat_run_event_cb(struct neat_internal_ctx *nic, uint8_t event_type,
        void *data)
{
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr = NULL;

    if (event_type > NEAT_MAX_EVENT)
        return;

    cb_list_head = &(nic->event_cbs[event_type]);

    for (cb_itr = cb_list_head->lh_first; cb_itr != NULL;
            cb_itr = cb_itr->next_cb.le_next)
        cb_itr->event_cb(nic, data);
}

uint8_t neat_remove_event_cb(struct neat_internal_ctx *nic, uint8_t event_type,
        struct neat_event_cb *cb)
{
    struct neat_event_cbs *cb_list_head;
    struct neat_event_cb *cb_itr = NULL;

    if (event_type > NEAT_MAX_EVENT ||
        !nic->event_cbs)
        return RETVAL_FAILURE;

    cb_list_head = &(nic->event_cbs[event_type]);

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

