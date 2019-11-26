#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <limits.h>
#include <sys/stat.h>
#include <uv.h>
#include <jansson.h>
#include <pthread.h>
#include <getopt.h>

#include <time.h>

#include "pib.h"
#include "rest.h"
#include "cib.h"
#include "pm_helper.h"
#include "parse_json.h"
#include "version.h"

#define PM_BACKLOG 128
#define PM_BUFSIZE 65536

#define NUM_CANDIDATES 10

uv_loop_t *loop;
pthread_t thread_id_rest;

typedef struct client_req {
    char *buffer;
    size_t len;
} client_req_t;

json_t *
lookup(json_t *reqs)
{
    json_t *updated_requests;
    json_t *request;
    json_t *candidate;
    json_t *candidates;
    json_t *policy_candidates;
    json_t *cib_candidates;
    json_t *cib_lookup_result; //TODO RENAME
    size_t i, j, k;

    int new_candidates;

    json_t* req_expand = expand_properties(reqs);

    if(verbose) {
        print_separator("═");
        pretty_print(req_expand, false);
        print_separator("═");
    }

    json_t* requests = process_special_properties(req_expand);

    json_array_foreach(requests, i, request) {
        add_default_values(request);
    }

    if (pre_resolve(requests)) {
        write_log(__FILE__, __func__, LOG_DEBUG, "__request_type is pre-resolve, skipping lookup.");
        return requests;
    }
    else  {
	    write_log(__FILE__, __func__, LOG_EVENT, "Starting lookup...");
        if(verbose)
            print_separator("─");
    }

    json_t *expanded_requests = expand_values(requests);
    size_t len = json_array_size(expanded_requests);

    candidates = json_array();

    json_array_foreach(expanded_requests, i, request) {
        if(verbose) {
            write_log(__FILE__, __func__, LOG_EVENT, "Processing request %d/%d:", i + 1, len);
            pretty_print(request, false);
            write_log(__FILE__, __func__, LOG_EVENT, "\nProfile lookup...");
        }

        /* Profile lookup */
        updated_requests = profile_lookup(request);
        new_candidates = json_array_size(updated_requests);

        if(verbose) {
            write_log(__FILE__, __func__, LOG_EVENT, "    Profile lookup returned %d candidate(s)", new_candidates);
            if(new_candidates == 0) {
                json_decref(updated_requests);
                write_log(__FILE__, __func__, LOG_EVENT, "    No candidates, skipping request...", new_candidates);
                print_separator("─");
                continue;
            }
        }

        new_candidates = 0;
        if(verbose)
            write_log(__FILE__, __func__, LOG_EVENT, "CIB lookup...");

        cib_candidates = json_array();

        /* CIB lookup */
        json_array_foreach(updated_requests, j, candidate){
            cib_lookup_result = cib_lookup(candidate);
            json_array_foreach(cib_lookup_result, k, candidate){
                if(!array_contains_value(cib_candidates, candidate)){
                    new_candidates++;
                    json_array_append_new(cib_candidates, json_deep_copy(candidate));
                }
            }
            json_decref(cib_lookup_result);
        }
        json_decref(updated_requests);

        if(verbose) {
            write_log(__FILE__, __func__, LOG_EVENT, "    CIB lookup returned %d candidate(s)", new_candidates);
        }

        new_candidates = 0;
        if(verbose)
            write_log(__FILE__, __func__, LOG_EVENT, "PIB lookup...");

        /* Policy lookup */
        json_array_foreach(cib_candidates, j, candidate) {
            policy_candidates = policy_lookup(candidate);
            json_array_foreach(policy_candidates, k, candidate){
                if(!array_contains_value(candidates, candidate)){
                    new_candidates++;
                    json_array_append(candidates, json_deep_copy(candidate));
                }
            }
            json_decref(policy_candidates);
        }
        json_decref(cib_candidates);

        if(verbose) {
            write_log(__FILE__, __func__, LOG_EVENT, "    PIB lookup returned %d candidate(s)", new_candidates);
            print_separator("─");
        }
    }

    json_array_foreach(candidates, i, request) {
        add_default_values(request);
    }

    candidates = sort_json_array(candidates);
    candidates = limit_json_array(candidates, NUM_CANDIDATES);
    
    /* Cleanup */
    json_decref(expanded_requests);

    if(verbose) {
        write_log(__FILE__, __func__, LOG_EVENT, "PM Top %d: ", NUM_CANDIDATES);
        print_separator("═");
        pretty_print(candidates, true);
        print_separator("═");
    }

    return candidates;
}

void
handle_request(uv_stream_t *client)
{
    client_req_t *client_req = (client_req_t *) client->data;
    uv_buf_t response_buf;
    uv_write_t *write_req;
    json_t *request_json;
    json_error_t json_error;
    uv_write_t wr;

    request_json = json_loads(client_req->buffer, 0, &json_error);
    write_log(__FILE__, __func__, LOG_EVENT, "Request(s) received");

    if (!request_json) {
        write_log(__FILE__, __func__, LOG_ERROR, "Error with request, json-error-text: %s", json_error.text);
        return;
    }

    clock_t start, end;
    start = clock();
    json_t *candidates = lookup(request_json);
    end = clock();

    double ms = (double)(end-start) / CLOCKS_PER_SEC * 1000;

    write_log(__FILE__, __func__, LOG_EVENT, "Lookup finished in %lf ms", ms);

    response_buf.base = json_dumps(candidates, 0);
    if(!response_buf.base) {
        write_log(__FILE__, __func__, LOG_ERROR, "Unable to parse candidate list");
        json_decref(request_json);
        json_decref(candidates);
        return;
    }

    response_buf.len = strlen(response_buf.base);

    write_log(__FILE__, __func__, LOG_EVENT, "Request handled, sending candidates\n");
    /* Make sure all is written before returning */
    while(uv_try_write(client, &response_buf, 1) == UV_EAGAIN) {} // TODO: do this in a better way

    free(response_buf.base);
    json_decref(candidates);
}

void
alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buffer)
{
    buffer->base = calloc(suggested_size, sizeof(char));

    if(buffer->base == NULL) {
        write_log(__FILE__, __func__, LOG_ERROR, "Failed to allocate memory");
    }

    buffer->len = suggested_size;
}

void
on_client_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buffer)
{
    client_req_t *c_req = (client_req_t *) client->data;

    if (nread == UV_EOF) {
        handle_request(client);

        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
    }
    else if (nread < 0) {
        write_log(__FILE__, __func__, LOG_ERROR, "Socket client read failure");

        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);

        free(client);
        return;
    }
    else {
        strncpy(c_req->buffer + c_req->len, buffer->base, PM_BUFSIZE - c_req->len);
        c_req->len += nread;
    }
    free(buffer->base);
}

void
on_new_pm_connection(uv_stream_t *pm_server, int status)
{
    uv_pipe_t *client;

    if (status == -1) {
        write_log(__FILE__, __func__, LOG_ERROR, "Socket new connection failure");
        return;
    }

    client = malloc(sizeof(uv_pipe_t));
    
    client->data = malloc(sizeof(client_req_t)); /* stores json request */
    client_req_t *c_req = (client_req_t *) client->data;

    c_req->buffer = malloc(PM_BUFSIZE);
    c_req->len = 0;

    uv_pipe_init(loop, client, 0);

    if (uv_accept(pm_server, (uv_stream_t *) client) == 0) {
        write_log(__FILE__, __func__, LOG_EVENT, "Accepted client request");
        uv_read_start((uv_stream_t *) client, alloc_buffer, on_client_read);
    }
    else {
        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
    }
}

void
handle_pib_request(uv_stream_t *client)
{
    json_t *json_for_node;
    json_error_t json_error;
    client_req_t *client_req = (client_req_t *) client->data;

    json_t *request_json = json_loads(client_req->buffer, 0, &json_error);

    if(!request_json) {
        write_log(__FILE__, __func__, LOG_ERROR, "%s", json_error.text);
        return;
    }

    if(json_is_array(request_json)) {
        add_pib_node(json_array_get(request_json, 0)); // Foreach?

    }
    else {
        add_pib_node(request_json);
    }

    json_decref(request_json);
}

void
on_pib_socket_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buffer)
{
    client_req_t *c_req = (client_req_t *) client->data;

    if (nread == UV_EOF) {
        handle_pib_request(client);

        free(c_req->buffer);
        free(c_req);;
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
    }
    else if (nread < 0) {
        write_log(__FILE__, __func__, LOG_ERROR, "PIB socket read error");
        
        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
        return;
    }
    else {
        strncpy(c_req->buffer + c_req->len, buffer->base, PM_BUFSIZE - c_req->len);
        c_req->len += nread;
    }
    free(buffer->base);
}

void
on_new_pib_connection(uv_stream_t *pib_server, int status)
{
    uv_pipe_t *client;

    if (status == -1) {
        write_log(__FILE__, __func__, LOG_ERROR, "PIB socket connection error");
        return;
    }

    client = malloc(sizeof(uv_pipe_t));
    client->data = malloc(sizeof(client_req_t)); /* stores json request */
    client_req_t *c_req = (client_req_t *) client->data;

    c_req->buffer = malloc(PM_BUFSIZE);
    c_req->len = 0;

    uv_pipe_init(loop, client, 0);

    if (uv_accept(pib_server, (uv_stream_t *) client) == 0) {
        write_log(__FILE__, __func__, LOG_EVENT, "Accepted PIB request");
        uv_read_start((uv_stream_t *) client, alloc_buffer, on_pib_socket_read);
    }
    else {
        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
    }
}

void
handle_cib_request(uv_stream_t *client)
{
    json_t *json_for_node;
    json_error_t json_error;
    client_req_t *client_req = (client_req_t *) client->data;

    json_t *request_json = json_loads(client_req->buffer, 0, &json_error);

    if(!request_json) {
        write_log(__FILE__, __func__, LOG_ERROR, "%s", json_error.text);
        return;
    }

    if(json_is_array(request_json)) {
        add_cib_node(json_array_get(request_json, 0));
    }
    else {
        add_cib_node(request_json);
    }

    json_decref(request_json);
}

void
on_cib_socket_read(uv_stream_t *client, ssize_t nread, const uv_buf_t *buffer)
{
    client_req_t *c_req = (client_req_t *) client->data;

    if (nread == UV_EOF) {
        handle_cib_request(client);

        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
    }
    else if (nread < 0) {
        write_log(__FILE__, __func__, LOG_ERROR, "CIB socket read error");

        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
        return;
    }
    else {
        strncpy(c_req->buffer + c_req->len, buffer->base, PM_BUFSIZE - c_req->len);
        c_req->len += nread;
    }
    free(buffer->base);
}

void
on_new_cib_connection(uv_stream_t *cib_server, int status)
{
    uv_pipe_t *client;

    if (status == -1) {
        write_log(__FILE__, __func__, LOG_ERROR, "CIB socket connection error\n");
        return;
    }

    client = malloc(sizeof(uv_pipe_t));
    client->data = malloc(sizeof(client_req_t)); /* stores json request */
    client_req_t *c_req = (client_req_t *) client->data;

    c_req->buffer = malloc(PM_BUFSIZE);
    c_req->len = 0;

    uv_pipe_init(loop, client, 0);

    if (uv_accept(cib_server, (uv_stream_t *) client) == 0) {
        write_log(__FILE__, __func__, LOG_EVENT, "Accepted CIB request");
        uv_read_start((uv_stream_t *) client, alloc_buffer, on_cib_socket_read);
    }
    else {
        free(c_req->buffer);
        free(c_req);
        uv_close((uv_handle_t *) client, (uv_close_cb) free);
    }
}

void
pm_close(int sig)
{
    uv_fs_t req;
    uv_fs_unlink(loop, &req, pm_socket_path, NULL);
    uv_fs_unlink(loop, &req, cib_socket_path, NULL);
    uv_fs_unlink(loop, &req, pib_socket_path, NULL);

    pib_close();
    cib_close();
    pm_helper_close();

    // Stop REST API
    pthread_mutex_unlock(&stop_mutex);
    pthread_join(thread_id_rest, NULL);
    pthread_detach(thread_id_rest);
    
    write_log(__FILE__, __func__, LOG_EVENT, "\nClosing policy manager...\n");

    exit(sig);
}

//this function never returns, see documentation "uv_run"
int
create_sockets()
{
    uv_pipe_t pm_server;
    uv_pipe_t cib_server;
    uv_pipe_t pib_server;
    int r, s, t;

    loop = uv_default_loop();
    uv_pipe_init(loop, &pm_server, 0);
    uv_pipe_init(loop, &cib_server, 0);
    uv_pipe_init(loop, &pib_server, 0);

    signal(SIGINT, pm_close);

    unlink(pm_socket_path);
    unlink(cib_socket_path);
    unlink(pib_socket_path);

    if ((r = uv_pipe_bind(&pm_server, pm_socket_path)) != 0) {
        write_log(__FILE__, __func__, LOG_ERROR, "PM socket bind error %s", uv_err_name(r));
        return 1;
    }
    if ((r = uv_listen((uv_stream_t*) &pm_server, PM_BACKLOG, on_new_pm_connection))) {
        write_log(__FILE__, __func__, LOG_ERROR, "PM socket listen error %s", uv_err_name(r));
        return 2;
    }

    if ((s = uv_pipe_bind(&cib_server, cib_socket_path)) != 0) {
        write_log(__FILE__, __func__, LOG_ERROR, "CIB socket bind error %s", uv_err_name(r));
        return 1;
    }
    if ((s = uv_listen((uv_stream_t*) &cib_server, PM_BACKLOG, on_new_cib_connection))) {
        write_log(__FILE__, __func__, LOG_ERROR, "CIB socket listen error %s", uv_err_name(r));
        return 2;
    }

    if ((t = uv_pipe_bind(&pib_server, pib_socket_path)) != 0) {
        write_log(__FILE__, __func__, LOG_ERROR, "PIB socket bind error %s", uv_err_name(r));
        return 1;
    }
    if ((t = uv_listen((uv_stream_t*) &pib_server, PM_BACKLOG, on_new_pib_connection))) {
        write_log(__FILE__, __func__, LOG_ERROR, "PIB socket listen error %s", uv_err_name(r));
        return 2;
    }

    return uv_run(loop, UV_RUN_DEFAULT);
}

void
print_opt(const char *short_opt, const char *long_opt, const char *arg, const char *description)
{
    fprintf(stdout, "  -%s, --%s\t\t%s\t\t%s\n", short_opt, long_opt, arg, description);
}

void
usage() 
{
    fprintf(stdout, "%s %s\n\n", APPNAME, APPVERSION);
    fprintf(stdout, "usage: \t%s ", APPNAME);
    fprintf(stdout, "[--help] [--cib CIB] [--pib PIB] [--sock SOCK]\n");
    fprintf(stdout, "\t[--enable-cache] [--debug] [--log] [--verbose]\n\n");

    print_opt("h", "help", "", "show this message and quit");
    print_opt("c", "cib", "<path>", "specify directory in which to look for CIB files");
    print_opt("p", "pib", "<path>", "specify directory in which to look for PIB files");
    print_opt("s", "sock", "<path>", "set path for Unix domain sockets");
    print_opt("r", "rest-ip", "<addr>", "set local management IP:PORT for external REST calls");

    print_opt("C", "cache", "", "enable CIB cache");
    print_opt("d", "debug", "", "show debug messages");
    print_opt("l", "log", "", "write output to Log.txt");
    print_opt("v", "verbose", "", "show verbose output");

    return;
}

int
parse_arguments(int argc, char *argv[])
{
    while(1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"cache", no_argument, 0, 'C'},
            {"debug", no_argument, 0, 'd'},
            {"help", no_argument, 0, 'h'},
            {"log", no_argument, 0, 'l'},
            {"verbose", no_argument, 0, 'v'},
            {"cib", required_argument, 0, 'c'},
            {"pib", required_argument, 0, 'p'},
            {"sock", required_argument, 0, 's'},
            {"rest-ip", required_argument, 0, 'r'},
        };

        int arg = getopt_long(argc, argv, "Cdhlvc:p:s:r:", long_options, &option_index);
        if (arg == -1) {
            break;
        }

        char *tok;

        switch(arg) {
            /* Help */
            case 'h':
                usage();
                return false;
            /* CIB cache */
            case 'C':
                enable_cib_cache(true);
                break;
            /* Enable debug */
            case 'd':
                enable_debug_message(true);
                break;
            /* Enable logfile */
            case 'l':
                enable_log_file(true);
                break;
            /* Enable verbose output */
            case 'v':
                enable_verbose(true);
                break;
            /* CIB path */
            case 'c':
                if(!strcmp(optarg + strlen(optarg) - 1, "/")) {
                    cib_dir = new_string("%s", optarg);
                } else {
                    cib_dir = new_string("%s/", optarg);
                }
                break;
            /* PIB path */
            case 'p':
                if(!strcmp(optarg + strlen(optarg) - 1, "/")) {
                    pib_dir = new_string("%s", optarg);
                } else {
                    pib_dir = new_string("%s/", optarg);
                }
                break;
            /* Socket path */
            case 's':
                if(!strcmp(optarg + strlen(optarg) - 1, "/")) {
                    sock_dir = new_string("%s", optarg);
                } else {
                    sock_dir = new_string("%s/", optarg);
                }
                break;
            /* REST IP:PORT */
            case 'r':
                // Get IP-address
                tok = strtok(optarg, ":");
                if(!tok) {
                    write_log(__FILE__, __func__, LOG_ERROR, "Failed to parse option: -r, --rest-ip");
                    return false;
                }
                rest_ip = tok;
                // Get port if available
                tok = strtok(NULL, "");
                if(!tok) {
                    return true;
                }
                if(!(rest_port = atoi(tok))) {
                    write_log(__FILE__, __func__, LOG_ERROR, "Failed to parse option: -r, --rest-ip");
                    return false;
                }
                break;
            default:
                break;
        }
    }
    return true;
}

int
main(int argc, char *argv[])
{
    if(!parse_arguments(argc, argv)) {
        exit(EXIT_FAILURE);
    }
    if(!start_pm_helper()) {
        pm_helper_close();
        exit(EXIT_FAILURE);
    }

    generate_cib_from_ifaces();
    cib_start();
    pib_start();

    // start REST API
    pthread_mutex_lock(&stop_mutex);
    pthread_create(&thread_id_rest, NULL, rest_start, NULL);

    return create_sockets();
}
