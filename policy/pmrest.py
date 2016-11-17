import json
import logging

try:
    from aiohttp import web
except ImportError as e:
    web = None

LOCAL_IP = '0.0.0.0'
REST_PORT = 45888

pib = None
cib = None

server = None


async def handle_pib(request):
    uid = request.match_info.get('uid')
    if uid is None:
        text = json.dumps(list(pib.index.keys()))
        return web.Response(text=text)

    logging.info("PIB uid request for uid %s" % (uid))
    try:
        text = pib.index[uid].json()
    except KeyError as e:
        return web.Response(status=404, text='unknown UID')

    return web.Response(text=text)


async def handle_cib(request):
    uid = request.match_info.get('uid')
    if uid is None:
        text = json.dumps(list(cib.uid.keys()))
        return web.Response(text=text)

    logging.info("CIB uid request for uid %s" % (uid))
    try:
        text = str(cib[uid])
    except KeyError as e:
        return web.Response(status=404, text='unknown UID')

    return web.Response(text=text)


async def handle_rest(request):
    name = str(request.match_info.get('name')).lower()
    if name not in ('pib', 'cib'):
        # FIXME return proper response
        return web.Response(status=404)
    uid = request.match_info.get('uid', 0)

    text = "request for %s %s" % (name, uid)
    return web.Response(text=text)


def init_rest_server(asyncio_loop, pib_ref, cib_ref, rest_port=None):
    """ Register REST server
    """
    if web is None:
        logging.info("REST server not available because the aiohttp module is not installed.")
        return

    global pib, cib, REST_PORT, server

    pib = pib_ref
    cib = cib_ref

    if rest_port:
        REST_PORT = rest_port

    app = web.Application()
    app.router.add_get('/', handle_rest)
    # app.router.add_get('/{name}/{uid}', handle_rest)
    app.router.add_get('/pib', handle_pib)
    app.router.add_get('/pib/{uid}', handle_pib)

    app.router.add_get('/cib', handle_cib)
    app.router.add_get('/cib/{uid}', handle_cib)

    handler = app.make_handler()

    f = asyncio_loop.create_server(handler, LOCAL_IP, REST_PORT)
    print("Initializing REST server on port %d" % REST_PORT)

    server = asyncio_loop.run_until_complete(f)


def close():
    server.close()
