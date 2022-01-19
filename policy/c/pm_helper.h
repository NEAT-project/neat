#ifndef HEADER_PM_HELPER
#define HEADER_PM_HELPER

#include <time.h>
#include <jansson.h>
#include <stdbool.h>

#define PRECEDENCE_BASE 0
#define PRECEDENCE_OPTIONAL 1
#define PRECEDENCE_IMMUTABLE 2

// OUTPUT STYLES
#define UNDERLINE "\033[4m"
#define UNDERLINE_END "\033[24m"
#define LIGHT_GREY "\033[37m"
#define DARK_GREY "\033[90m"
#define NORMAL "\033[0m"

// DEFAULT PATHS
#define DEFAULT_PM_PATH (new_string("%s/%s/", get_home_dir(), ".neat"))
#define DEFAULT_SOCK_PATH (new_string("%s/%s/", get_home_dir(), ".neat"))
#define DEFAULT_PIB_PATH (new_string("%s/%s/%s/", get_home_dir(), ".neat", "pib"))
#define DEFAULT_CIB_PATH (new_string("%s/%s/%s/", get_home_dir(), ".neat", "cib"))

// DEFAULT REST PARAMETERS
#define DEFAULT_REST_IP "0.0.0.0"
#define DEFAULT_REST_PORT 45888

#define min(a, b) (a < b ? a : b)

/* For stopping the REST-API */
pthread_mutex_t stop_mutex;

extern char* neat_dir;
extern char* sock_dir;
extern char* cib_dir;
extern char* pib_dir;
extern char* profile_dir;
extern char* policy_dir;

extern char *pm_socket_path;
extern char *cib_socket_path;
extern char *pib_socket_path;

extern char *rest_ip;
extern int rest_port;

extern bool debug_enabled;
extern bool cib_cache_enabled;
extern bool verbose;

extern int CIB_DEFAULT_TIMEOUT;

typedef enum {
    LOG_EVENT, LOG_ERROR, LOG_DEBUG, LOG_NEW_LINE, LOG_NO_NEW_LINE
} LOG_LEVEL;

void enable_log_file(bool enable);
void enable_debug_message(bool enable);
void enable_cib_cache(bool enable);
void enable_verbose(bool enable);
void write_log(const char* module, const char* func, LOG_LEVEL log_level, const char *desc, ...);
void print_separator(const char *sep);

void pm_helper_close();
bool create_folder(const char* path);
void init_pm_helper();
bool start_pm_helper();
char* new_string(char *string, ...);
int file_exist(const char * file_path);
char *get_home_dir();

time_t file_edit_time(const char *file_path);
void clear_log_file();
int file_is_modified(const char *path, time_t old_time);
json_t* load_json_file(const char *file_path);
void write_json_file(const char* file_path, json_t *json);
bool array_contains_value(json_t *array, json_t *value);
char *get_hash();
double get_time_monotonic();

#endif
