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

try:
    resthelper_loaded = True
    import resthelper
except ImportError as e:
    resthelper_loaded = False

profiles = None
cib = None
pib = None

server = None

app = None
loop = None


def gen_hello_msg():
    host_info = {'host-uid': PM.CLIENT_UID,
                 'management-address': PM.REST_IP,
                 'rest-port': PM.REST_PORT,
                 'client-type': 'neat'}

    if resthelper_loaded:
        ips = resthelper.get_local_ips()
        host_info['local-addresses'] = ips
    else:
        logging.warning('Local addresses not available')
    hello_msg = json.dumps({"input": host_info})
    return hello_msg


async def controller_announce():
    """
    Register NEAT client with a remote controller
    and send hello message every PM.CONTROLLER_ANNOUNCE seconds

    """
    if not PM.CONTROLLER_REST:
        return

    while True:
        sleep_time = min(random.expovariate(1 / PM.CONTROLLER_ANNOUNCE), PM.CONTROLLER_ANNOUNCE * 3)

        print("Notifying controller at %s (repeat in %1.0fs)" % (PM.CONTROLLER_REST, sleep_time))

        conn = aiohttp.TCPConnector(local_addr=(PM.REST_IP, 0))
        auth = aiohttp.BasicAuth(PM.CONTROLLER_USER, PM.CONTROLLER_PASS)

        async with aiohttp.ClientSession(connector=conn, auth=auth) as session:
            try:
                async with session.post(PM.CONTROLLER_REST, data=gen_hello_msg(),
                                        headers={'content-type': 'application/json'}) as resp:
                    # logging.debug('announce addr: %s:%s' % resp.connection._protocol.transport.get_extra_info('sockname'))
                    if resp.status != 200:
                        logging.warning("Controller provided an invalid response")
                        print(resp)
                    html = await resp.text()

            except (ValueError, aiohttp.ClientConnectionError) as e:
                print(e)

        await asyncio.sleep(sleep_time)


async def handle_refresh(request):
    logging.info("Reloading PIB...")
    pib.reload_files()
    logging.info("Reloading profiles...")
    profiles.reload_files()
    logging.info("Reloading CIB...")
    cib.reload_files()

    return web.Response(text='PM repositories reloaded.')


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
    assert request.content_type == 'application/json'
    uid = request.match_info.get('uid')
    logging.info("Received new policy entry with uid \'%s\'" % (uid))

    new_policy = await request.text()
    pib.import_json(new_policy, uid)
    return web.Response(text="OK")


async def handle_pib_delete(request):
    """
    Delete PIB entry with specific UID 

    Test using: curl -H 'Content-Type: application/json' -X DELETE localhost:45888/pib/1234
    """
    assert request.content_type == 'application/json'
    uid = request.match_info.get('uid')
    logging.info("Removing policy entry with uid \'%s\'" % (uid))

    try:
        pib.remove(uid)
    except KeyError:
        text = "Policy not found (uid \'%s\')." % uid
        logging.warning(text)
        return web.Response(status=404, text=text)
    return web.Response(text="Policy removed")


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


async def handle_cib_delete(request):
    """
    Delete CIB node with specific UID 

    Test using: curl -H 'Content-Type: application/json' -X DELETE localhost:45888/cib/1234
    """
    assert request.content_type == 'application/json'
    uid = request.match_info.get('uid')
    logging.info("Removing CIB node with uid \'%s\'" % (uid))

    try:
        cib.remove(uid)
    except KeyError:
        text = "CIB node not found (uid \'%s\')." % uid
        logging.warning(text)
        return web.Response(status=404, text=text)
    return web.Response(text="CIB node removed")


async def handle_rest(request):
    name = str(request.match_info.get('name')).lower()
    if name not in ('pib', 'cib'):
        # FIXME return proper response
        return web.Response(status=404)
    uid = request.match_info.get('uid', 0)

    text = "request for %s %s" % (name, uid)
    return web.Response(text=text)


def init_rest_server(asyncio_loop, profiles_ref, cib_ref, pib_ref, rest_port=None):
    """ 
    Initialize and register REST server.
    """
    if web is None:
        logging.info("REST server not available because the aiohttp module is not installed.")
        return

    global pib, cib, profiles, port, server, loop, app

    loop = asyncio_loop

    cib = cib_ref
    pib = pib_ref
    profiles = profiles_ref

    if rest_port:
        PM.REST_PORT = rest_port

    pmrest = web.Application()
    app = pmrest

    pmrest.router.add_get('/', handle_rest)
    pmrest.router.add_get('/reload', handle_refresh)

    pmrest.router.add_get('/pib', handle_pib)
    pmrest.router.add_get('/pib/{uid}', handle_pib)

    pmrest.router.add_get('/cib', handle_cib)
    pmrest.router.add_get('/cib/{uid}', handle_cib)
    pmrest.router.add_get('/cib/rows', handle_cib_rows)

    pmrest.router.add_put('/cib/{uid}', handle_cib_put)
    pmrest.router.add_put('/pib/{uid}', handle_pib_put)

    pmrest.router.add_delete('/pib/{uid}', handle_pib_delete)
    pmrest.router.add_delete('/cib/{uid}', handle_cib_delete)

    handler = pmrest.make_handler()

    f = asyncio_loop.create_server(handler, PM.REST_IP, PM.REST_PORT)
    print("Initializing REST server on %s:%d" % (PM.REST_IP, PM.REST_PORT))
    try:
        server = asyncio_loop.run_until_complete(f)
    except OSError as e:
        print(e)
        return

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
