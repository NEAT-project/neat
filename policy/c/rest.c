#include <stdio.h>
#include <netinet/in.h>
#include <ulfius.h>
#include <arpa/inet.h>
#include <jansson.h>
#include <pthread.h>

#include "pib.h"
#include "cib.h"
#include "pm_helper.h"

int
callback_get_pib(const struct _u_request * request, struct _u_response * response, void * user_data) {
    char msg[256];

    json_t *pib = get_pib_list();

    if (pib) {
        ulfius_set_json_body_response(response, 200, pib);
    }
    else {
        write_log(__FILE__, __func__, LOG_DEBUG, "REST-API: pib not found");
        ulfius_set_string_body_response(response, 404, "[]");
    }
    json_decref(pib);

    return U_CALLBACK_CONTINUE;
}

int
callback_get_cib(const struct _u_request * request, struct _u_response * response, void * user_data) {
    char msg[256];

    json_t *cib = get_cib_list();

    if (cib) {
        ulfius_set_json_body_response(response, 200, cib);
    }
    else {
        write_log(__FILE__, __func__, LOG_DEBUG, "REST-API: cib not found");
        ulfius_set_string_body_response(response, 404, "[]");
    }
    json_decref(cib);

    return U_CALLBACK_CONTINUE;
}

int
callback_get_rows(const struct _u_request * request, struct _u_response * response, void * user_data) {
    char msg[256];

    json_t *rows = get_rows();

    if (rows) {
        ulfius_set_json_body_response(response, 200, rows);
    }
    else {
        write_log(__FILE__, __func__, LOG_DEBUG, "REST-API: rows not found");
        ulfius_set_string_body_response(response, 404, "[]");
    }

    return U_CALLBACK_CONTINUE;
}

int
callback_get_pib_node(const struct _u_request * request, struct _u_response * response, void * user_data) {
    const char *uid = u_map_get(request->map_url, "uid");
    write_log(__FILE__, __func__, LOG_DEBUG, "REST-API: Request for pib uid \"%s\"", uid);

    json_t *policy = get_pibnode_by_uid(uid);

    if (policy) {
        ulfius_set_json_body_response(response, 200, policy);
    }
    else {
        write_log(__FILE__, __func__, LOG_DEBUG, "REST-API: pib with ID \"%s\" not found", uid);
        ulfius_set_string_body_response(response, 404, "unknown UID");
    }

    return U_CALLBACK_CONTINUE;
}

int
callback_get_cib_node(const struct _u_request * request, struct _u_response * response, void * user_data) {
    const char *uid = u_map_get(request->map_url, "uid");

    json_t *cibnode = get_cibnode_by_uid(uid);

    if (cibnode) {
        ulfius_set_json_body_response(response, 200, cibnode);
    }
    else {
        write_log(__FILE__, __func__, LOG_DEBUG, "REST-API: node ID \"%s\" not found", uid);
        ulfius_set_string_body_response(response, 404, "unknown UID");
    }

    return U_CALLBACK_CONTINUE;
}

int
callback_put_pib_node(const struct _u_request * request, struct _u_response * response, void * user_data) {
    json_error_t error;
    const char *uid = u_map_get(request->map_url, "uid");
    json_t *json_request = ulfius_get_json_body_request(request, &error);
    if(json_request)
    {
        if(!json_object_get(json_request, "uid")) {
            json_object_set(json_request, "uid", json_string(uid));
        }
        if(!json_object_get(json_request, "properties")){
            write_log(__FILE__, __func__, LOG_ERROR, "REST-API: PIB JSON object missing mandatory field");
            ulfius_set_string_body_response(response, 400, "JSON object missing mandatory field");
        } else {
            add_pib_node(json_request);
            ulfius_set_string_body_response(response, 200, "OK");
        }
        json_decref(json_request);
    } else {
        write_log(__FILE__, __func__, LOG_DEBUG,  "REST-API: JSON not found");
        ulfius_set_string_body_response(response, 400, "unknown UID");
    }
    return U_CALLBACK_CONTINUE;
}

int
callback_put_cib_node(const struct _u_request * request, struct _u_response * response, void * user_data) {
    json_error_t error;
    const char *uid = u_map_get(request->map_url, "uid");
    json_t *json_request = ulfius_get_json_body_request(request, &error);
    
    if(json_request)
    {
        if(!json_object_get(json_request, "uid")) {
            json_object_set(json_request, "uid", json_string(uid));
        }
        if(!json_object_get(json_request, "properties")){
            write_log(__FILE__, __func__, LOG_ERROR, "REST-API: CIB JSON object missing mandatory field");
            ulfius_set_string_body_response(response, 400, "JSON object missing mandatory field");
        } else {
            add_cib_node(json_request);
            ulfius_set_string_body_response(response, 200, "OK");
        }
        json_decref(json_request);
    } else {
        write_log(__FILE__, __func__, LOG_ERROR, "REST-API: JSON not found");
        ulfius_set_string_body_response(response, 400, "JSON object not found");
    }
    return U_CALLBACK_CONTINUE;
}

int
callback_delete_pib_node(const struct _u_request * request, struct _u_response * response, void * user_data) {
    json_error_t error;
    const char *uid = u_map_get(request->map_url, "uid");
    
    if(!uid) {
        write_log(__FILE__, __func__, LOG_ERROR, "REST-API: Request missing mandatory field");
        ulfius_set_string_body_response(response, 400, "Invalid request");
    } else {
        remove_pib_node(uid);
        ulfius_set_string_body_response(response, 200, "OK");
    }
    return U_CALLBACK_CONTINUE;
}

int
callback_delete_cib_node(const struct _u_request * request, struct _u_response * response, void * user_data) {
    json_error_t error;
    const char *uid = u_map_get(request->map_url, "uid");
    
    if(!uid) {
        write_log(__FILE__, __func__, LOG_ERROR, "REST-API: Request missing mandatory field");
        ulfius_set_string_body_response(response, 400, "Invalid request");
    } else {
        remove_cib_node(uid);
        ulfius_set_string_body_response(response, 200, "OK");
    }
    return U_CALLBACK_CONTINUE;
}

int
rest_start(int argc, char **argv){
    struct _u_instance instance;
    struct sockaddr_in addr;

    if(!rest_ip) {
        rest_ip = DEFAULT_REST_IP;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(rest_port);
    int a = inet_pton(AF_INET, rest_ip, &addr.sin_addr);

    // Initialize instance with the port number
    if (ulfius_init_instance(&instance, rest_port, &addr, NULL) != U_OK) {
        write_log(__FILE__, __func__, LOG_ERROR, "REST API failure, ulfius_init_instance, abort\n");
        return(1);
    }

    // Endpoint list declaration
    ulfius_add_endpoint_by_val(&instance, "GET", "/pib", "", 0, &callback_get_pib, NULL);
    ulfius_add_endpoint_by_val(&instance, "GET", "/cib", "", 0, &callback_get_cib, NULL);
    ulfius_add_endpoint_by_val(&instance, "GET", "/cib", "/rows", 1, &callback_get_rows, NULL);
    ulfius_add_endpoint_by_val(&instance, "GET", "/pib", "/:uid", 0, &callback_get_pib_node, NULL);
    ulfius_add_endpoint_by_val(&instance, "GET", "/cib", "/:uid", 0, &callback_get_cib_node, NULL);
    ulfius_add_endpoint_by_val(&instance, "PUT", "/pib", "/:uid", 0, &callback_put_pib_node, NULL);
    ulfius_add_endpoint_by_val(&instance, "PUT", "/cib", "/:uid", 0, &callback_put_cib_node, NULL);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/pib", "/:uid", 0, &callback_delete_pib_node, NULL);
    ulfius_add_endpoint_by_val(&instance, "DELETE", "/cib", "/:uid", 0, &callback_delete_cib_node, NULL);

    // Start the framework
    if (ulfius_start_framework(&instance) == U_OK) {
        write_log(__FILE__, __func__, LOG_EVENT, "Starting REST-API on port %s:%d", rest_ip, instance.port);
        /* Wait for mutex unlock */
        pthread_mutex_lock(&stop_mutex);
        // Do nothing
        pthread_mutex_unlock(&stop_mutex);
    } else {
        write_log(__FILE__, __func__, LOG_ERROR, "Failed to start REST-API");
    }
    write_log(__FILE__, __func__, LOG_EVENT,"Closing REST-API...");

    ulfius_stop_framework(&instance);
    ulfius_clean_instance(&instance);

    return 0;
}
