#ifndef NEAT_SECURITY_H
#define NEAT_SECURITY_H

#ifdef NEAT_USETLS
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/engine.h>
#include <openssl/x509.h>
#endif

#endif
