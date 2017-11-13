#include <neat.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>


#include "util.h"
#include "picohttpparser.h"

#define QUOTE(...) #__VA_ARGS__

/**********************************************************************

    http server

**********************************************************************/

static char *config_property = QUOTE(
    {"transport":
        {"value":["TCP","SCTP"],"precedence":1}
    }
);

static char *config_property_https  = QUOTE(
    {
        "transport": [
            {
                "value": "TCP",
                "precedence": 1
            }
        ],
        "security" :
            {
                "value": true,
                "precedence": 2
            }
    }
);
static uint8_t config_log_level     = 1;
static uint8_t config_keep_alive    = 0;
static uint8_t config_https         = 1;
static char *htdocs_directory       = "htdocs"; // without trailing slash!!
#define BUFFERSIZE 33768
#define BUFFERSIZE_SMALL 1024
struct neat_ctx *ctx = NULL;


static char *http_header_connection_keep_alive  = "Connection: Keep-Alive";

static neat_error_code on_writable(struct neat_flow_operations *opCB);

struct http_flow {
    unsigned char buffer[BUFFERSIZE];
    char *method;
    char *path;
    int minor_version;
    int pret;
    struct phr_header headers[100];
    size_t buffer_len;
    size_t buffer_len_prev;
    size_t method_len;
    size_t path_len;
    size_t num_headers;
    uint8_t keep_alive;
};

void
sig_handler(int signo) {

    if (signo == SIGINT) {
        printf("received SIGINT - stopping event loop\n");
        neat_stop_event_loop(ctx);
    }
}

static int
prepare_http_response(struct http_flow *http_flow, unsigned char **buffer, uint32_t *buffer_len) {

    int header_length               = 0;
    int payload_length              = 0;
    unsigned char *payload_buffer   = NULL;
    unsigned char *header_buffer    = NULL;
    int i                           = 0;
    char misc_buffer[BUFFERSIZE_SMALL];


    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    // iterate header fields
    for (i = 0; i < (int)http_flow->num_headers; i++) {
        // build string from name/value pair
        snprintf(misc_buffer, BUFFERSIZE_SMALL, "%.*s: %.*s",
            (int)http_flow->headers[i].name_len,
            http_flow->headers[i].name,
            (int)http_flow->headers[i].value_len,
            http_flow->headers[i].value);

        // we have a Keep-Alive connection
        if (strncasecmp(misc_buffer, http_header_connection_keep_alive, strlen(http_header_connection_keep_alive)) == 0 &&
            config_keep_alive == 1) {
            http_flow->keep_alive = 1;
        }

    }

    // XXX needs refactoring - just shit ... shame on me... :/
    if (http_flow->path_len == 1 && http_flow->path[0] == '/') {
        // request root "/" --> index.html
        snprintf(misc_buffer, sizeof(misc_buffer), "%s/index.html", htdocs_directory);
    } else if (http_flow->path_len > 1 && http_flow->path[0] == '/') {
        // path begins with "/"
        snprintf(misc_buffer, sizeof(misc_buffer), "%s/%.*s", htdocs_directory, (int)http_flow->path_len - 1, http_flow->path + 1);
    } else {
        // path does not begin with "/"
        snprintf(misc_buffer, sizeof(misc_buffer), "%s/%.*s", htdocs_directory, (int)http_flow->path_len, http_flow->path);
    }

    // try to read requested file
    payload_length = read_file(misc_buffer, (char **) &payload_buffer);


    if (payload_length < 0) {
        // error when reading file - read index.html
        if (config_log_level >= 1) {
            fprintf(stderr, "%s - reading >>%s<< failed -  delivering index.html\n", __func__, misc_buffer);
        }
        snprintf(misc_buffer, sizeof(misc_buffer), "htdocs/index.html");
        payload_length = read_file(misc_buffer, (char **) &payload_buffer);
    }

    if (payload_length < 0 ) {
        // we have a serious problem here...
        fprintf(stderr, "%s - read_file failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    header_buffer = malloc(BUFFERSIZE_SMALL);
    if (header_buffer == NULL) {
        fprintf(stderr, "%s - malloc failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    // prepare response header
    header_length = snprintf((char *) header_buffer, BUFFERSIZE_SMALL,
        "HTTP/1.1 200 OK\r\n"
        "Server: NEAT super fancy webserver\r\n"
        "Content-Length: %u\r\n"
        "Connection: %s\r\n"
        "\r\n",
        payload_length,
        http_flow->keep_alive ? "Keep-Alive" : "Close");

    if (header_length == -1) {
        fprintf(stderr, "%s - asprintf failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    if (config_log_level >= 1) {
        // print response information
        fprintf(stderr, "\n\n%s\n", header_buffer);
    }


    header_buffer = realloc(header_buffer, header_length + payload_length);

    if (header_buffer == NULL) {
        fprintf(stderr, "%s - realloc failed\n", __func__);
        exit(EXIT_FAILURE);
    }

    memcpy(header_buffer + header_length, payload_buffer, payload_length);
    free(payload_buffer);

    *buffer = header_buffer;
    *buffer_len = header_length + payload_length;

    return NEAT_OK;
}



/*
    print usage and exit
*/
static void
print_usage()
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    printf("server_http [OPTIONS]\n");
    printf("\t- P <filename> \tneat properties, default properties:\n%s\n", config_property);
    printf("\t- v \tlog level 0..2 (%d)\n", config_log_level);
}

/*
    Error handler
*/
static neat_error_code
on_error(struct neat_flow_operations *opCB)
{

    fprintf(stderr, "%s()\n", __func__);
    //return 0;
    exit(EXIT_FAILURE);
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    neat_error_code code;
    struct http_flow *http_flow = opCB->userData;
    uint32_t buffer_filled = 0;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    code = neat_read(opCB->ctx, opCB->flow, http_flow->buffer + http_flow->buffer_len, BUFFERSIZE - http_flow->buffer_len, &buffer_filled, NULL, 0);
    if (code != NEAT_OK) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read failed - code: %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }

    if (config_log_level >= 1) {
        printf("%s - read %d byte\n", __func__, buffer_filled);
    }


    http_flow->buffer_len_prev  = http_flow->buffer_len;
    http_flow->buffer_len       += buffer_filled;
    http_flow->num_headers      = sizeof(http_flow->headers) / sizeof(http_flow->headers[0]);

    http_flow->pret = phr_parse_request((const char *) http_flow->buffer,
        http_flow->buffer_len,
        (const char **) &(http_flow->method),
        &(http_flow->method_len),
        (const char **) &(http_flow->path),
        &(http_flow->path_len),
        &(http_flow->minor_version),
        http_flow->headers,
        &(http_flow->num_headers),
        http_flow->buffer_len_prev);

    if (http_flow->pret > 0) {
        // request parsed successfully
        opCB->on_writable = on_writable;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
        return NEAT_OK;
    } else if (http_flow->pret == -1) {
        fprintf(stderr, "%s - error : parsing request!\n", __func__);
        neat_close(opCB->ctx, opCB->flow);
        return NEAT_OK;
    }

    assert(http_flow->pret == -2);
    if (http_flow->buffer_len == sizeof(http_flow->buffer)) {
        fprintf(stderr, "%s - error : request to long!!\n", __func__);
        neat_close(opCB->ctx, opCB->flow);
        return NEAT_OK;
    }

    // continue reading
    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    struct http_flow *http_flow = opCB->userData;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (http_flow->keep_alive == 1) {
        memset(http_flow, 0, sizeof(struct http_flow));
        opCB->on_all_written = NULL;
        opCB->on_readable = on_readable;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
    } else {
        neat_close(opCB->ctx, opCB->flow);
    }

    return NEAT_OK;
}

static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    struct http_flow *http_flow = opCB->userData;
    unsigned char *buffer       = NULL;
    uint32_t buffer_len         = 0;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (config_log_level >= 1) {
        // print request information
        printf("#######################################################\n");
        printf("request is %d bytes long\n", http_flow->pret);
        printf("method is %.*s\n", (int)http_flow->method_len, http_flow->method);
        printf("path is %.*s\n", (int)http_flow->path_len, http_flow->path);
        printf("HTTP version is 1.%d\n", http_flow->minor_version);
        printf("headers:\n");
        for (int i = 0; i != (int)http_flow->num_headers; ++i) {
            printf("%.*s: %.*s\n",
                (int)http_flow->headers[i].name_len,
                http_flow->headers[i].name,
                (int)http_flow->headers[i].value_len,
                http_flow->headers[i].value);
        }
        printf("#######################################################\n");
    }

    if (prepare_http_response(http_flow, &buffer, &buffer_len) != NEAT_OK) {
        exit(EXIT_FAILURE);
    }


    code = neat_write(opCB->ctx, opCB->flow, buffer, buffer_len, NULL, 0);
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write failed - code: %d\n", __func__, (int)code);
        return on_error(opCB);
    }

    free(buffer);

    opCB->on_writable = NULL;
    opCB->on_all_written = on_all_written;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);


    return NEAT_OK;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 1) {
        fprintf(stderr, "%s - flow closed OK!\n", __func__);
    }
    free(opCB->userData);
    return NEAT_OK;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (config_log_level >= 1) {
        printf("peer connected\n");
    }

    if ((opCB->userData = calloc(1, sizeof(struct http_flow))) == NULL) {
        fprintf(stderr, "%s - could not allocate http_flow\n", __func__);
        exit(EXIT_FAILURE);
    }

    opCB->on_readable = on_readable;
    opCB->on_writable = NULL;
    opCB->on_all_written = NULL;
    opCB->on_close = on_close;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    // uint64_t prop;
    int arg, result;
    char *arg_property              = NULL;
    struct neat_flow *flow_http     = NULL;
    struct neat_flow *flow_https    = NULL;
    struct neat_flow_operations ops_http;
    struct neat_flow_operations ops_https;

    memset(&ops_http, 0, sizeof(struct neat_flow_operations));
    memset(&ops_https, 0, sizeof(struct neat_flow_operations));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "P:v:k")) != -1) {
        switch(arg) {
        case 'P':
            if (read_file(optarg, &arg_property) < 0) {
                fprintf(stderr, "Unable to read properties from %s: %s",
                        optarg, strerror(errno));
                result = EXIT_FAILURE;
                goto cleanup;
            }
            if (config_log_level >= 1) {
                printf("option - properties: %s\n", arg_property);
            }
            break;
        case 'v':
            config_log_level = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - log level: %d\n", config_log_level);
            }
            break;
        case 'k':
            config_keep_alive = 1;
            if (config_log_level >= 1) {
                printf("option - Keep-Alive: %d\n", config_keep_alive);
            }
            break;
        default:
            print_usage();
            goto cleanup;
            break;
        }
    }

    if (optind != argc) {
        fprintf(stderr, "%s - argument error\n", __func__);
        print_usage();
        goto cleanup;
    }

    if ((ctx = neat_init_ctx()) == NULL) {
        fprintf(stderr, "%s - neat_init_ctx failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (config_log_level == 0) {
        neat_log_level(ctx, NEAT_LOG_ERROR);
    } else if (config_log_level == 1){
        neat_log_level(ctx, NEAT_LOG_WARNING);
    } else {
        neat_log_level(ctx, NEAT_LOG_DEBUG);
    }

    // new neat flow
    if ((flow_http = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set properties
    if (neat_set_property(ctx, flow_http, arg_property ? arg_property : config_property)) {
        fprintf(stderr, "%s - neat_set_property failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // set callbacks
    ops_http.on_connected   = on_connected;
    ops_http.on_error       = on_error;

    if (neat_set_operations(ctx, flow_http, &ops_http)) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    // wait for on_connected or on_error to be invoked
    if (neat_accept(ctx, flow_http, 8080, NULL, 0)) {
        fprintf(stderr, "%s - neat_accept failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (config_https) {
        // new neat flow
        if ((flow_https = neat_new_flow(ctx)) == NULL) {
            fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        // set properties
        if (neat_set_property(ctx, flow_https, config_property_https)) {
            fprintf(stderr, "%s - neat_set_property failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        // set callbacks
        ops_https.on_connected   = on_connected;
        ops_https.on_error       = on_error;

        if (neat_set_operations(ctx, flow_https, &ops_https)) {
            fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        if (neat_secure_identity(ctx, flow_https, "cert.pem", NEAT_CERT_KEY_PEM)) {
            fprintf(stderr, "%s - neat_get_secure_identity failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

        // wait for on_connected or on_error to be invoked
        if (neat_accept(ctx, flow_https, 8081, NULL, 0)) {
            fprintf(stderr, "%s - neat_accept failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }

    }

    //if (chdir("htdocs")) {
    //    fprintf(stderr, "%s - chdir failed\n", __func__);
    //}

    if (signal(SIGINT, sig_handler) == SIG_ERR) {
        fprintf(stderr, "%s - can not register SIGINT\n", __func__);
    }

    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);

    // cleanup
cleanup:
    if (arg_property)
        free(arg_property);

    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
