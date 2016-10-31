#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include <sys/stat.h>
#include <uv.h>

#include "../neat.h"
#include "../neat_internal.h"

/**********************************************************************

    peer

        TODO Tidy up code, client() and server() should be functions
        TODO Write receved file to disk

**********************************************************************/

static uint32_t config_buffer_size_max = 1400;
static uint16_t config_log_level = 0;
static char config_property[] = "NEAT_PROPERTY_UDP_REQUIRED";
static uint32_t config_drop_randomly= 0;
static uint32_t config_drop_rate= 80;
static uint32_t config_port=6969;

#define SEGMENT_SIZE 1024
#define SECOND 1000

const char *filename;
int sender = 0;
struct fileinfo *fi;
uint32_t retry_limit = 10;

#define explode() fprintf(stdout, "EXPLOSIVE ERRROR %s:%d\n",__func__, __LINE__);\
        exit(0);

#define ACK 1
#define CONNECT 2
#define CONNECTACK 3
#define COMPLETE 6
#define DATA 4
#define ERROR 254

struct header {
    uint8_t cmd;
    uint8_t flags;
    uint32_t size;

    uint32_t data_size;
    unsigned char *data;        /* ptr into buf */
};

struct peer {
    struct header *hdr;
    uint8_t sendcmd;

    uint8_t connected;
    uint8_t connecting;
    uint8_t master;
    uint8_t complete;

    uv_timer_t *timer;
    uint32_t retry_count;

    unsigned char *buffer;
    uint32_t buffer_size;
    uint32_t buffer_alloc;

    unsigned char *file_buffer;
    uint32_t file_buffer_size;
    uint32_t file_buffer_alloc;

    uint32_t segment;
    uint32_t segments_count;
    char *file_name;

    struct fileinfo *fi;
};

struct fileinfo
{
    uint32_t size;
    uint32_t segments;
    char *filename;
    FILE *stream;
};

static neat_error_code on_writable(struct neat_flow_operations *opCB);
static void on_timeout(uv_timer_t *);

int parsemsg(struct header *, unsigned char *, size_t);
int preparemsg(unsigned char *, uint32_t, uint32_t * ,uint8_t, uint8_t,
        uint32_t, unsigned char *, uint32_t );

struct peer * alloc_peer();
void free_peer(struct peer *);

int append_data(struct peer *, unsigned char *, size_t );

struct fileinfo * openfile(const char *, const char *);
void freefileinfo(struct fileinfo *);

int random_loss();

int
random_loss()
{
    if (!config_drop_randomly)
        return 0;

    return ((uint32_t) random() % 100) > config_drop_rate;
}

struct fileinfo *
openfile(const char *filename, const char *mode)
{
    struct fileinfo *fi;
    struct stat st;
	uint8_t write = 0;

    fi = calloc(1, sizeof(struct fileinfo));

    if (fi == NULL) {
		fprintf(stderr, "%s - could not calloc fileinfo struct\n", __func__);
		return NULL;
    }

	if(strstr(filename, "\\") != NULL || strstr(filename, "/") != NULL) {
		fprintf(stderr, "%s - banned characters in file path '\\' or '/'\n", __func__);
		free(fi);
		return NULL;
	}

	if(strstr(mode,"w") != NULL) {
		write = 1;
	}

    if (stat(filename, &st) == -1) {
		if(write == 0) {
			fprintf(stderr, "%s - file not found\n", __func__);
			free(fi);
			return NULL;
		}
    }

    fi->size = st.st_size;
    fi->segments = (fi->size+SEGMENT_SIZE-1)/SEGMENT_SIZE; /* round up */
    fi->filename = strdup(filename);

    fi->stream = fopen(filename, mode);

    if (fi->stream == NULL) {
		free(fi->filename);
		free(fi);
		fprintf(stderr, "%s - file not found\n", __func__);
		return NULL;
    }

    return fi;
}

void
freefileinfo( struct fileinfo *fi)
{
    if (fclose(fi->stream) != -1) {
            fprintf(stderr, "%s - failed to close file\n", __func__);
            perror("closing file");
    }
    free(fi->filename);
    free(fi);
}

int
preparemsg(unsigned char *buf, uint32_t bufsz, uint32_t *actualsz, uint8_t cmd,
        uint8_t flags, uint32_t size, unsigned char *data, uint32_t data_size)
{
    size_t headsz = sizeof(cmd) + sizeof(flags) + sizeof(size);

    if ( bufsz < (data_size + headsz)) {
            return -1;
    }

    *actualsz = data_size+headsz;

    buf[0] = cmd;
    buf[1] = flags;
    //buf[2] = htonl(size);
    uint32_t nsize = htonl(size);

    memcpy(buf+2, &nsize, sizeof(uint32_t));

    if( data_size > 0 && data != NULL) {
            memcpy(buf+headsz, data, *actualsz);
    }

    return 1;
}

struct peer *
alloc_peer()
{
    struct peer *p;

    if ((p = calloc(1, sizeof(struct peer))) == NULL) {
        goto out;
    }

    if ((p->hdr = calloc(1, sizeof(struct header))) == NULL) {
        goto out;
    }

    p->buffer_alloc = config_buffer_size_max;

    if ((p->buffer = calloc(p->buffer_alloc, sizeof(unsigned char))) == NULL) {
        goto out;
    }

    p->file_buffer_alloc = 128*1024;
    p->file_buffer_size = 0;

    if ((p->file_buffer = calloc(p->file_buffer_alloc, sizeof(unsigned char))) == NULL) {
        goto out;
    }

    /* create and initialise the timer */
    if ((p->timer = calloc(1, sizeof(uv_timer_t ))) == NULL) {
        goto out;
    }

    return p;

out:
    if (p == NULL)
        return NULL;

    free(p->timer);
    free(p->file_buffer);
    free(p->buffer);
    free(p->hdr);
    free(p);

    return NULL;
}

void
free_peer(struct peer *p)
{
    free(p->file_name);
    free(p->file_buffer);
    free(p->buffer);
    free(p->hdr);
    free(p);
}

int
append_data(struct peer *p, unsigned char *buffer, size_t size)
{
    if(p->file_buffer_size+size < p->file_buffer_alloc) {
        memcpy(p->file_buffer + p->file_buffer_size, buffer, size);
		p->file_buffer_size += size;
        return 0;
    } else {
        fprintf(stderr, "%s():%d file buffer exhausted \n", __func__,__LINE__);
		explode();
		return 1;
	}
}

int
parsemsg(struct header *hdr, unsigned char *buffer, size_t buffersize)
{
    uint32_t nsize;
    size_t headsz = sizeof(hdr->cmd) + sizeof(hdr->flags) + sizeof(hdr->size);

    if (buffersize < headsz) {
        fprintf(stderr, "%s():%d %s\n", __func__,__LINE__, "buffersize < headsz");
        return 0;
    }

    hdr->cmd = buffer[0];
    hdr->flags = buffer[1];

    memcpy(&nsize, buffer+2, sizeof(uint32_t));

    hdr->size = ntohl(nsize);

    if (buffersize > headsz) {
        hdr->data = buffer+headsz;
        hdr->data_size = buffersize-headsz;
    }

    return 1;
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

    printf("peer [OPTIONS]\n");
    printf("\t- P \tneat properties (%s)\n", config_property);
    printf("\t- S \tbuffer in byte (%d)\n", config_buffer_size_max);
    printf("\t- v \tlog level 0..3 (%d)\n", config_log_level);
    printf("\t- h \thost\n");
    printf("\t- p \tport (%d)\n", config_port);
    printf("\t- f filename.txt \tsend file\n");
    printf("\t- D (%d)\tartificially drop packets\n", config_drop_rate);
}


/*
    Error handler
*/
static neat_error_code
on_error(struct neat_flow_operations *opCB)
{
    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }
	explode();

    exit(EXIT_FAILURE);
}

static neat_error_code
on_readable(struct neat_flow_operations *opCB)
{
    // data is available to read
    neat_error_code code;
    struct peer *pf = opCB->userData;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

	/* kill any running timer */
	uv_timer_stop(pf->timer);
	pf->retry_count = 0;

    code = neat_read(opCB->ctx, opCB->flow, pf->buffer, pf->buffer_alloc, &pf->buffer_size, NULL, 0);
    if (code != NEAT_OK) {
        if (code == NEAT_ERROR_WOULD_BLOCK) {
            if (config_log_level >= 1) {
                printf("on_readable - NEAT_ERROR_WOULD_BLOCK\n");
            }
            return NEAT_OK;
        } else {
            fprintf(stderr, "%s - neat_read error: %d\n", __func__, (int)code);
            return on_error(opCB);
        }
    }


    // we got some data
    if (pf->buffer_size > 0) {
        if (config_log_level >= 1) {
            printf("received data - %d byte\n", pf->buffer_size);
        }
        if (config_log_level >= 2) {
            fwrite(pf->buffer, sizeof(char), pf->buffer_size, stdout);
            printf("\n");
            fflush(stdout);
        }

		if(random_loss()) {
			if (config_log_level >= 1) {
				printf("received data - %d byte, throwing it away\n", pf->buffer_size);
				return NEAT_OK;
			}
		}

        struct header *hdr = pf->hdr;
        if (!parsemsg(hdr, pf->buffer, pf->buffer_size)) {
            explode();
        }

        switch(hdr->cmd) {
        case CONNECT:
            if (!pf->master) {
                pf->sendcmd = CONNECTACK;
                pf->file_name = strndup((char *)hdr->data, hdr->data_size);
                pf->segments_count = hdr->size;
                pf->segment = 0;

				if (config_log_level >= 3) {
					fprintf(stderr, "%s:%d got CONNECT %d segments\n",
							__func__, __LINE__, pf->segments_count);
					fprintf(stderr, "%s:%d receiving filename: %s %d segments\n",
							__func__, __LINE__, pf->file_name, pf->segments_count);
				}
            } else {
                pf->sendcmd = ERROR;
            }
            break;
        case COMPLETE:
			if (config_log_level >= 3) {
				fprintf(stderr, "%s:%d got CONNECTACK %d segments\n",
					__func__, __LINE__, pf->segments_count);
			}
            pf->sendcmd = COMPLETE;
			pf->complete = 1;
            break;
        case CONNECTACK:
			if (config_log_level >= 3) {
				fprintf(stderr, "%s:%d got CONNECTACK %d segments\n",
					__func__, __LINE__, pf->segments_count);
			}
            pf->sendcmd = DATA;
            break;
        case DATA:
			if (config_log_level >= 3) {
				fprintf(stderr, "%s:%d got DATA %d segment\n",
					__func__, __LINE__, hdr->size);
			}

			if ((hdr->size == 0 && pf->segment == 0) || hdr->size == pf->segment+1) {

                append_data(pf, hdr->data, hdr->data_size);

                pf->sendcmd = ACK;
				if(hdr->size == pf->segment+1) {
					pf->segment++;
				}
			} else {
				if(hdr->size < pf->segment) {
					fprintf(stderr, "%s:%d duplicate segment, sending ACK\n",
						__func__, __LINE__);
					pf->sendcmd = ACK;
				} else {
					fprintf(stderr, "%s:%d unexpected segment, sending ERROR\n",
						__func__, __LINE__);
					pf->sendcmd = ERROR;
				}
			}
            break;
        case ACK:
			if (config_log_level >= 3) {
				fprintf(stderr, "%s:%d got ACK %d segment\n",
					__func__, __LINE__, hdr->size);
			}

			if (pf->segment == hdr->size) {
				if (pf->segment == pf->segments_count-1) {      /* if this was the final segment */
					pf->sendcmd = COMPLETE;
				} else {
					pf->sendcmd = DATA;
					if (config_log_level >= 3) {
						fprintf(stderr, "%s:%d ACK %d moving segment ptr\n",
							__func__, __LINE__, hdr->size);
					}
					pf->segment++;
				}
			} else {
					fprintf(stderr, "%s:%d ACK: unpected ACK got: %d, expected: %d\n",
						__func__, __LINE__, hdr->size, pf->segment);
					explode(); //differnet ack to sent segment
			}
            break;
        case ERROR:
			fprintf(stderr, "%s:%d Recevice ERROR\n",
					__func__, __LINE__);
            explode();
            break;
        default:
            explode();
            break;
        }
        opCB->on_readable = NULL;
        opCB->on_writable = on_writable;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
    // peer disconnected - stop callbacks and free ressources
    } else {
        if (config_log_level >= 1) {
            printf("peer disconnected\n");
        }
        opCB->on_readable = NULL;
        opCB->on_writable = NULL;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);
        free(pf->buffer);
        free(pf);
        neat_close(opCB->ctx, opCB->flow);
    }
    return NEAT_OK;
}

static neat_error_code
on_all_written(struct neat_flow_operations *opCB)
{
    struct peer *pf = opCB->userData;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }
    fprintf(stdout, ".");
	fflush(stdout);

    if (pf->complete) {
        uv_timer_stop(pf->timer);
        opCB->on_readable = NULL;
        opCB->on_writable = NULL;
        opCB->on_all_written = NULL;
        neat_set_operations(opCB->ctx, opCB->flow, opCB);

		if (!pf->master) {
			/* time to save and file then shut down*/
			struct fileinfo *fi;

			fi = openfile(pf->file_name,"w");
			if (fi == NULL) {
				fprintf(stderr, "%s:%d could not open file %s\n",
					__func__, __LINE__, pf->file_name);
			}

			fwrite(pf->file_buffer, sizeof(char), pf->file_buffer_size, fi->stream);
			fclose(fi->stream);
			freefileinfo(fi);
		}
		neat_close(opCB->ctx, opCB->flow);
        return NEAT_OK;
    }

    opCB->on_readable = on_readable;
    opCB->on_writable = NULL;
    opCB->on_all_written = NULL;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

	/*start a timer */
	uv_timer_start(pf->timer, on_timeout, 1*SECOND, 1*SECOND);

    return NEAT_OK;
}

static neat_error_code
on_writable(struct neat_flow_operations *opCB)
{
    neat_error_code code;
    struct peer *pf = opCB->userData;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    // set callbacks
    opCB->on_readable = NULL;
    opCB->on_writable = NULL;
    opCB->on_all_written = on_all_written;
    neat_set_operations(opCB->ctx, opCB->flow, opCB);

    switch(pf->sendcmd) {

    case CONNECT:
    	if (config_log_level >= 3) {
			fprintf(stderr, "%s:%d CONNECT'ing with filename: %s\n",
									__func__, __LINE__, filename);
		}
        //pf->master = 0;
        pf->segments_count = pf->fi->segments;

                preparemsg(pf->buffer, pf->buffer_alloc, &pf->buffer_size, CONNECT, 0,
                        pf->segments_count, (unsigned char *)filename, sizeof(filename));

        break;
    case COMPLETE:
    	if (config_log_level >= 3) {
			fprintf(stderr, "%s:%d Sending COMPLETE%d\n",
									__func__, __LINE__, pf->segments_count);
		}
		preparemsg(pf->buffer, pf->buffer_alloc, &pf->buffer_size, COMPLETE,
				0, pf->segments_count, NULL, 0);
        break;
    case CONNECTACK:
    	if (config_log_level >= 3) {
			fprintf(stderr, "%s:%d CONNECTACK acking segments %d\n",
									__func__, __LINE__, pf->segments_count);
		}
		preparemsg(pf->buffer, pf->buffer_alloc, &pf->buffer_size, CONNECTACK,
				0, pf->segments_count, NULL, 0);
        break;
    case DATA:
    	if (config_log_level >= 3) {
			fprintf(stderr, "%s:%d Sending DATA Segment %d\n",
									__func__, __LINE__, pf->segment);
			fprintf(stderr, "%s:%d Sending bytes from %ld plus %d\n",
									__func__, __LINE__,
									ftell(pf->fi->stream), SEGMENT_SIZE);
		}
		unsigned char buf[SEGMENT_SIZE];
		size_t bytes;

		fseek(pf->fi->stream, pf->segment*SEGMENT_SIZE, SEEK_SET);
		bytes = fread(buf, sizeof(unsigned char), SEGMENT_SIZE, pf->fi->stream);
		if (bytes == 0) {
			if(feof(pf->fi->stream)) {
				fprintf(stderr, "%s:%d Sending DATA Segment %d hit EOF\n",
					__func__, __LINE__, pf->segment);
				//pf->sendcmd = COMPLETE;
				//explode();
				return NEAT_OK;
			} else {
				explode();
			}
		}

		preparemsg(pf->buffer, pf->buffer_alloc, &pf->buffer_size, DATA,
				0, pf->segment, buf, bytes);
        break;
    case ACK:
    	if (config_log_level >= 3) {
			fprintf(stderr, "%s:%d ACK acking segment %d\n",
									__func__, __LINE__, pf->segment);
		}
		preparemsg(pf->buffer, pf->buffer_alloc, &pf->buffer_size, ACK,
				0, pf->segment, NULL, 0);
        break;
    case ERROR:
    	if (config_log_level >= 3) {
			fprintf(stderr, "%s:%d Sending ERROR\n",
									__func__, __LINE__);
		}
		preparemsg(pf->buffer, pf->buffer_alloc, &pf->buffer_size, ERROR,
				0, 0, NULL, 0);
		pf->complete = 1;
        break;

    default:
        explode();
        break;
    }

    code = neat_write(opCB->ctx, opCB->flow, pf->buffer, pf->buffer_size, NULL, 0);
    if (code != NEAT_OK) {
        fprintf(stderr, "%s - neat_write error: %d\n", __func__, (int)code);
        return on_error(opCB);
    }

    if (config_log_level >= 1) {
        printf("sent data - %d byte\n", pf->buffer_size);
    }

    return NEAT_OK;
}

static void
on_timeout(uv_timer_t *handle)
{
	struct neat_flow_operations *opCB = handle->data;
	struct peer *pf;

    fprintf(stderr, "%s:%d %s\n", __func__, __LINE__, "timeout firing");


	pf = opCB->userData;
	if(pf->retry_count++ > retry_limit) {
			pf->sendcmd = ERROR;
	}

	opCB->on_readable = NULL;
	opCB->on_writable = on_writable;
	opCB->on_all_written = NULL;
	neat_set_operations(opCB->ctx, opCB->flow, opCB);

	return;
}

static neat_error_code
on_connected(struct neat_flow_operations *opCB)
{
    struct peer *pf = NULL;

    if (config_log_level >= 2) {
        fprintf(stderr, "%s()\n", __func__);
    }

    if (config_log_level >= 1) {
        printf("peer connected\n");
    }

    if ((opCB->userData = alloc_peer()) == NULL) {
        fprintf(stderr, "%s - could not allocate peer\n", __func__);
        exit(EXIT_FAILURE);
    }

	neat_set_qos(opCB->ctx, opCB->flow, 0x2e);
	neat_set_ecn(opCB->ctx, opCB->flow, 0x00);

	pf = opCB->userData;
	uv_timer_init(opCB->ctx->loop, pf->timer);
	pf->timer->data = opCB;

    if ((pf->buffer = malloc(config_buffer_size_max)) == NULL) {
        fprintf(stderr, "%s - could not allocate buffer\n", __func__);
        exit(EXIT_FAILURE);
    }

	if(sender) {
		sender = 0;
		pf->master = 1;
		pf->sendcmd = CONNECT;
		pf->fi = fi;

		opCB->on_readable = NULL;
		opCB->on_writable = on_writable;
		opCB->on_all_written = NULL;
		opCB->on_connected = NULL;
	} else {
		opCB->on_readable = on_readable;
		opCB->on_writable = NULL;
		opCB->on_all_written = NULL;
	}

    neat_set_operations(opCB->ctx, opCB->flow, opCB);
    return NEAT_OK;
}

static neat_error_code
on_close(struct neat_flow_operations *opCB)
{
    struct peer *pf = NULL;
	pf = opCB->userData;

	opCB->on_readable = NULL;
	opCB->on_writable = NULL;
	opCB->on_all_written = NULL;
	neat_set_operations(opCB->ctx, opCB->flow, opCB);

	if (pf->master) {
		neat_stop_event_loop(opCB->ctx);
	}
	free_peer(pf);

    return NEAT_OK;
}

int
main(int argc, char *argv[])
{
    int arg, result;
    char *arg_property = config_property;
    char *target_addr = NULL;
    static struct neat_ctx *ctx = NULL;
    static struct neat_flow *flow = NULL;
    static struct neat_flow_operations ops;

    memset(&ops, 0, sizeof(ops));

    result = EXIT_SUCCESS;

    while ((arg = getopt(argc, argv, "P:S:v:h:p:f:D:")) != -1) {
        switch(arg) {
        case 'P':
            arg_property = optarg;
            if (config_log_level >= 1) {
                printf("option - properties: %s\n", arg_property);
            }
            break;
        case 'S':
            config_buffer_size_max = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - buffer size: %d\n", config_buffer_size_max);
            }
            break;
        case 'v':
            config_log_level = atoi(optarg);
            if (config_log_level >= 1) {
                printf("option - log level: %d\n", config_log_level);
            }
            break;
        case 'h':
            target_addr = optarg;
            break;
        case 'p':
            config_port = atoi(optarg);
            break;
        case 'D':
            config_drop_rate = atoi(optarg);
			config_drop_randomly = 1;
            break;
        case 'f':
            sender = 1;
            if (config_log_level >= 1) {
                printf("option - acting as master(sending): %d\n", config_log_level);
            }
			filename = strdup(optarg);
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

    // new neat flow
    if ((flow = neat_new_flow(ctx)) == NULL) {
        fprintf(stderr, "%s - neat_new_flow failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

#if 0
    // set properties
    if (neat_set_property(ctx, flow, prop)) {
        fprintf(stderr, "%s - neat_set_property failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }
#endif

    // set callbacks
    ops.on_connected = on_connected;
    ops.on_close = on_close;
    ops.on_error = on_error;

    if (neat_set_operations(ctx, flow, &ops)) {
        fprintf(stderr, "%s - neat_set_operations failed\n", __func__);
        result = EXIT_FAILURE;
        goto cleanup;
    }

    if (sender) {
        fi = openfile(filename, "r");
        if (fi == NULL) {
            fprintf(stderr, "%s - failed to open file\n", __func__);
            perror("opening file");
            goto cleanup;
        }

		fprintf(stdout, "sending %s (%d bytes, %d segments) to %s:%d\n",
			filename, fi->size,fi->segments, target_addr, 6969);

        if (neat_open(ctx, flow, target_addr, config_port, NULL, 0) != NEAT_OK) {
            fprintf(stderr, "%s - neat_accept failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }
    } else {
        // wait for on_connected or on_error to be invoked
        if (neat_accept(ctx, flow, config_port, NULL, 0) != NEAT_OK) {
            fprintf(stderr, "%s - neat_accept failed\n", __func__);
            result = EXIT_FAILURE;
            goto cleanup;
        }
    }

    srandom(time(NULL));
    neat_start_event_loop(ctx, NEAT_RUN_DEFAULT);
	fprintf(stderr, "\ndisconnected from peer %s\n", target_addr);

    // cleanup
cleanup:
    if (ctx != NULL) {
        neat_free_ctx(ctx);
    }
    exit(result);
}
