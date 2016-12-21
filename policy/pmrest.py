import json
import logging
import uuid

import asyncio

import pmdefaults as PM

try:
    import aiohttp
    from aiohttp import web
except ImportError as e:
    web = None
    logging.warning("aiohttp in required to start the REST interface, but it is not installed")

# REST port
port = None

profiles = None
cib = None
pib = None

server = None


async def send_hello(client, controller):

    host_uid = str(uuid.uuid3(uuid.NAMESPACE_OID, str(uuid.getnode())))
    host_info = {'client-uid': host_uid,
                 'client-type': 'neat',
                 'manager-address': controller}
    hello_msg = json.dumps({"input": host_info})

    try:
        async with client.post(controller, data=hello_msg) as resp:
            assert resp.status == 200
            return await resp.text()
    except (ValueError, aiohttp.errors.ClientOSError) as e:
        print(e)


async def controller_announce(loop):
    """
    Register NEAT client with a remote controller

    """
    if not PM.CONTROLLER_REST:
        return

    # send hello message every PM.CONTROLLER_ANNOUNCE seconds
    # TODO randomize
    while True:
        print("Notifying controller at %s" % PM.CONTROLLER_REST)
        async with aiohttp.ClientSession(loop=loop) as client:
            html = await send_hello(client, PM.CONTROLLER_REST)
        await asyncio.sleep(PM.CONTROLLER_ANNOUNCE)


async def handle_pib(request):
    uid = request.match_info.get('uid')
    if uid is None:
        text = json.dumps(list(pib.index.keys()))
        return web.Response(text=text)

    logging.info("PIB request for uid %s" % (uid))

    try:
        text = pib.index[uid].json()
    except KeyError as e:
        return web.Response(status=404, text='unknown UID')

    return web.Response(text=text)


async def handle_pib_put(request):
    """

    Test using: curl -H 'Content-Type: application/json' -T test.policy localhost:45888/pib/23423
    """

    uid = request.match_info.get('uid')

    assert request.content_type == 'application/json'

    logging.info("Received new policy entry with uid %s" % (uid))

    new_cib = await request.text()
    pib.import_json(new_cib, uid)
    return web.Response(text="OK")


async def handle_cib_rows(request):
    rows = []
    for i in cib.rows:
        rows.append(i.dict())
    text = json.dumps(rows, indent=4)
    return web.Response(text=text)


async def handle_cib(request):
    uid = request.match_info.get('uid')
    if uid is None:
        text = json.dumps(list(cib.keys()))
        return web.Response(text=text)

    logging.info("CIB request for uid %s" % (uid))
    try:
        text = cib[uid].json()
    except KeyError as e:
        return web.Response(status=404, text='unknown UID')

    return web.Response(text=text)


async def handle_cib_put(request):
    uid = request.match_info.get('uid')
    if uid is None:
        text = json.dumps(list(cib.keys()))
        return web.Response(text=text)

    assert request.content_type == 'application/json'

    logging.info("new CIB entry with uid %s" % (uid))

    new_cib = await request.text()
    cib.import_json(new_cib, uid)
    return web.Response(text="OK")


async def handle_rest(request):
    name = str(request.match_info.get('name')).lower()
    if name not in ('pib', 'cib'):
        # FIXME return proper response
        return web.Response(status=404)
    uid = request.match_info.get('uid', 0)

    text = "request for %s %s" % (name, uid)
    return web.Response(text=text)


def init_rest_server(asyncio_loop, profiles_ref, cib_ref, pib_ref, rest_port=None):
    """ Register REST server

    curl  -H 'Content-Type: application/json' -X PUT -d'["adfd",123]'ocalhost:45888/cib/23423
    """
    if web is None:
        logging.info("REST server not available because the aiohttp module is not installed.")
        return

    global pib, cib, port, server

    profiles = profiles_ref
    cib = cib_ref
    pib = pib_ref

    if rest_port:
        port = rest_port

    pmrest = web.Application()
    pmrest.router.add_get('/', handle_rest)
    pmrest.router.add_get('/pib', handle_pib)
    pmrest.router.add_get('/pib/{uid}', handle_pib)

    pmrest.router.add_get('/cib', handle_cib)
    pmrest.router.add_get('/cib/rows', handle_cib_rows)
    pmrest.router.add_get('/cib/{uid}', handle_cib)

    pmrest.router.add_put('/cib/{uid}', handle_cib_put)
    pmrest.router.add_put('/pib/{uid}', handle_pib_put)

    handler = pmrest.make_handler()

    f = asyncio_loop.create_server(handler, PM.LOCAL_IP, port)
    print("Initializing REST server on port %d" % port)

    server = asyncio_loop.run_until_complete(controller_announce(asyncio_loop))

    server = asyncio_loop.run_until_complete(f)


def close():
    server.close()
