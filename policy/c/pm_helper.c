#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <pwd.h>
#include <limits.h>

#include "pm_helper.h"

#define LOG_FILENAME "Log.txt"

char* neat_dir = NULL;
char* sock_dir = NULL;
char* cib_dir = NULL;
char* pib_dir = NULL;
char* profile_dir = NULL;
char* policy_dir = NULL;

char* pm_socket_path = NULL;
char* cib_socket_path = NULL;
char* pib_socket_path = NULL;

char *rest_ip = NULL;
int rest_port = DEFAULT_REST_PORT;

int CIB_DEFAULT_TIMEOUT = 60*10;

bool debug_enabled = false;
bool log_file_enabled = false;
bool cib_cache_enabled = false;
bool verbose = false;

char*
get_home_dir()
{
    char *homedir;

    homedir = getenv("HOME");

    if (homedir == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
    }

    return homedir;
}

char*
get_current_dir(){
    char buf[1014];

    if (getcwd(buf, sizeof(buf)) != NULL) {
        char *dir = new_string(buf);
        return dir;
    } else {
        write_log(__FILE__ , __func__, LOG_ERROR, "Unable to get current directory..");
        return "";
    }
}

bool
create_folder(const char *path)
{
    char tmp[PATH_MAX];
    char *p = NULL;
    size_t len;
    struct stat st = {0};

    len = snprintf(tmp, sizeof(tmp), "%s", path);
    if(tmp[len - 1] == '/') {
        tmp[len - 1] = 0;
    }

    for(p = tmp + 1; *p; p++) {
        if(*p == '/') {
            *p = 0;
            if (stat(tmp, &st) == -1) {
                if(mkdir(tmp, 0700) == -1) {
                    write_log(__FILE__, __func__,LOG_ERROR, "Failed to create directory: %s, error message: %s", path, strerror(errno));
                    return false;
                }
            }
            *p = '/';
        }
    }

    if (stat(path, &st) == -1) {
        if(mkdir(tmp, 0700) == -1) {
            write_log(__FILE__, __func__,LOG_ERROR, "Failed to create directory: %s, error message: %s", path, strerror(errno));
            return false;
        }
    }
    return true;
}

bool
create_folders()
{
    neat_dir = DEFAULT_PM_PATH;

    if(!cib_dir) {
        cib_dir = DEFAULT_CIB_PATH;
    }
    if(!pib_dir) {
        pib_dir = DEFAULT_PIB_PATH;
    }

    profile_dir = new_string("%s%s", pib_dir, "profile/");
    policy_dir  = new_string("%s%s", pib_dir, "policy/");

    write_log(__FILE__, __func__, LOG_EVENT, "Creating CIB in %s", cib_dir);
    write_log(__FILE__, __func__, LOG_EVENT, "Creating PIB in %s", pib_dir);

    return create_folder(cib_dir) && create_folder(profile_dir) && create_folder(policy_dir);
}

void 
pm_helper_close()
{
    free(neat_dir);
    free(sock_dir);
    free(cib_dir);
    free(pib_dir);
    free(profile_dir);
    free(policy_dir);

    free(pm_socket_path);
    free(cib_socket_path);
    free(pib_socket_path);
}

bool 
create_socket_paths() {
    if(!sock_dir) {
        sock_dir = DEFAULT_SOCK_PATH;
    }

    pm_socket_path  = new_string("%s%s", sock_dir, "neat_pm_socket");
    cib_socket_path = new_string("%s%s", sock_dir, "neat_cib_socket");
    pib_socket_path = new_string("%s%s", sock_dir, "neat_pib_socket");

    write_log(__FILE__, __func__, LOG_EVENT, "Socket created in %s", pm_socket_path);
    write_log(__FILE__, __func__, LOG_EVENT, "Socket created in %s", cib_socket_path);
    write_log(__FILE__, __func__, LOG_EVENT, "Socket created in %s", pib_socket_path);
    write_log(__FILE__, __func__, LOG_NEW_LINE, "\n");

    return true;
}

bool 
start_pm_helper() 
{
    return create_folders() && create_socket_paths();
}


char*
new_string(char *string, ...)
{
    char buffer[1000];
	va_list arglist;

	va_start(arglist, string);
	vsprintf(buffer, string, arglist);
	va_end(arglist);

    const size_t len = strlen(buffer);
    char *result = calloc(1, len + 1); // +1 for the null-terminator

    if(result == NULL) {
         write_log(__FILE__, __func__, LOG_ERROR, "Failed to allocate memory");
         return NULL;
    }

    memcpy(result, buffer, len);
    return result;
}

int
file_exist(const char * file_path)
{
   return access(file_path, F_OK) != -1;
}

void
enable_log_file(bool enable)
{
    if(enable) {
        char* current_dir = get_current_dir();
        write_log(__FILE__, __func__, LOG_EVENT, "Log messages: %s/%s", current_dir, LOG_FILENAME);
        free(current_dir);
    }
    log_file_enabled = enable;
}

void
enable_debug_message(bool enable)
{
    debug_enabled = enable;
    if(enable)
        write_log(__FILE__, __func__, LOG_EVENT, "Debug mode: ON");
}

void
enable_cib_cache(bool enable)
{
    cib_cache_enabled = enable;
    if(enable)
        write_log(__FILE__, __func__, LOG_EVENT, "CIB cache: ON");
}

void
enable_verbose(bool enable)
{
    verbose = enable;
    if(enable)
        write_log(__FILE__, __func__, LOG_EVENT, "Verbose output: ON");
}

bool
is_log_enabled()
{
    return cib_cache_enabled;
}

bool
is_debug_enabled()
{
    return cib_cache_enabled;
}

bool
is_cache_enabled()
{
    return cib_cache_enabled;
}

void
write_log(const char* module, const char* func, LOG_LEVEL log_level, const char* format, ...)
{
    char* log_type;
    switch(log_level) {
        case LOG_EVENT:
            log_type = "EVENT";
            break;
        case LOG_ERROR:
            log_type = "ERROR";
            printf("[ERROR] ");
            break;
        case LOG_DEBUG:
            log_type = "DEBUG";
            if(debug_enabled) {
                printf("[DEBUG] ");
            }
            break;
        case LOG_NEW_LINE:
            printf("\n");
            return;
        default:
            break;
    }

    //write to console
    if(log_level != LOG_DEBUG || debug_enabled) {
        va_list argptr;
        va_start(argptr, format);

        vprintf(format, argptr);
        if(log_level != LOG_NO_NEW_LINE) { printf("\n"); }
        //if(log_level == LOG_ERROR) { printf("\n"); }

        va_end(argptr);
    }

    //write to log file
    if(log_file_enabled) {
        FILE *fp = fopen(LOG_FILENAME, "a");
        if(fp != NULL) {
            va_list argptr;
            va_start(argptr, format);

            char time_buffer[100];
            time_t now = time (0);
            strftime (time_buffer, 100, "%Y-%m-%d %H:%M:%S.000", localtime (&now));

            fprintf(fp, "Log Type: %s\nTime: %s  \nModule: %s\nFunction: %s\nDescription: ", log_type, time_buffer, module, func);
            vfprintf(fp, format, argptr);
            fprintf(fp, "\n\n");

            fclose(fp);
            va_end(argptr);
        }
        else {
            write_log(__FILE__ , __func__, LOG_ERROR, "Cannot access log file");
        }
    }
}

void
print_separator(const char *sep)
{
    struct winsize size;
    int i;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &size);

    for(i = 0; i < MIN(size.ws_col, 284); i++) {
        write_log(__FILE__, __func__, LOG_NO_NEW_LINE, sep);
    }
    write_log(__FILE__, __func__, LOG_NEW_LINE, "");
}

time_t
file_edit_time(const char *file_path)
{
    struct stat attr;
    stat(file_path, &attr);
    return attr.st_mtime;
}

void
clear_log_file()
{
    FILE *fp = fopen(LOG_FILENAME, "w");
    if(fp != NULL) {
        fclose(fp);
    }
}

//Returns 0 if file is not found
int
file_is_modified(const char *path, time_t old_time)
{
    struct stat file_stat;
    int err = stat(path, &file_stat);
    if (err != 0) {
        write_log(__FILE__ , __func__, LOG_ERROR, "Failure when reading: %s", path);
    }
    return file_stat.st_mtime > old_time;
}


json_t*
load_json_file(const char *file_path)
{
    if(file_path == NULL) { return NULL; }

    json_error_t error;
    json_t *json = json_load_file(file_path, 0, &error);

    if(!json) {
        write_log(__FILE__, __func__, LOG_ERROR, "Failed to read json file: %s",file_path);
    }
    return json;
}

void
write_json_file(const char* file_path, json_t *json)
{
    if(json_dump_file(json, file_path, JSON_INDENT(4)) == -1) {
        write_log(__FILE__, __func__, LOG_ERROR, "Unable to generate JSON file %s", file_path);
    }
}

bool
array_contains_value(json_t *array, json_t *value)
{
    size_t i;
    json_t *elem;
    json_array_foreach(array, i, elem) {
        if (json_equal(elem, value)) {
            return true;
        }
    }
    return false;
}

char *
get_hash()
{
    int hash_length = 30;
    char *hash = malloc((hash_length+1) * sizeof(char));
    time_t t;
    srandom((unsigned) time(&t));

    const char *charset = "0123456789abcdef";

    for (int i = 0; i < hash_length; i++) {
        *hash = *(charset + (random() % 16));  // Following chars in range 0..15
        hash++;
    }
    *hash = '\0';
    hash -= hash_length;
    return hash;
}
