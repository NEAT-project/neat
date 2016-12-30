import asyncio
import json
import logging
import random
from contextlib import suppress

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

app = None
loop = None


def gen_hello_msg():
    host_info = {'client-uid': PM.CLIENT_UID,
                 'client-rest-port': PM.REST_PORT,
                 'client-type': 'neat'}
    x = json.dumps({"input": host_info})
    return x


async def controller_announce():
    """
    Register NEAT client with a remote controller
    and send hello message every PM.CONTROLLER_ANNOUNCE seconds

    """
    if not PM.CONTROLLER_REST:
        return

    while True:
        sleep_time = min(random.expovariate(1 / PM.CONTROLLER_ANNOUNCE), PM.CONTROLLER_ANNOUNCE * 3)

        print("Notifying controller at %s (repeat in %1.2f s)" % (PM.CONTROLLER_REST, sleep_time))
        conn = aiohttp.TCPConnector()

        async with aiohttp.ClientSession(connector=conn) as client:
            try:
                async with client.post(PM.CONTROLLER_REST, data=gen_hello_msg()) as resp:
                    # resp.connection._protocol.transport.get_extra_info('sockname')
                    assert resp.status == 200
                    html = await resp.text()
            except (ValueError, aiohttp.errors.ClientOSError) as e:
                print(e)

        await asyncio.sleep(sleep_time)


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
    """ Initialize and register REST server

    curl  -H 'Content-Type: application/json' -X PUT -d'["abc",123]' localhost:45888/c3b/23423
    """
    if web is None:
        logging.info("REST server not available because the aiohttp module is not installed.")
        return

    global pib, cib, port, server, loop, app

    loop = asyncio_loop

    profiles = profiles_ref
    cib = cib_ref
    pib = pib_ref

    if rest_port:
        port = rest_port

    pmrest = web.Application()
    app = pmrest

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
    server = asyncio_loop.run_until_complete(f)

    asyncio.ensure_future(controller_announce())


def close():
    # cancel all running tasks:
    pending = asyncio.Task.all_tasks()
    for task in pending:
        task.cancel()
        # Now we should await task to execute it's cancellation.
        # Cancelled task raises asyncio.CancelledError that we can suppress:
        with suppress(asyncio.CancelledError):
            loop.run_until_complete(task)

    # TODO implement http://aiohttp.readthedocs.io/en/stable/web.html#graceful-shutdown
    server.close()
    loop.run_until_complete(server.wait_closed())

    loop.run_until_complete(app.shutdown())
    loop.run_until_complete(app.cleanup())
