import asyncio
import os
import pathlib
from unittest import mock

import pytest
from yarl import URL

import aiohttp
from aiohttp import hdrs, web


@pytest.fixture
def proxy_server(aiohttp_raw_server, aiohttp_server,
                 ssl_ctx, client_ssl_ctx,
                 loop):
    # Handle all proxy requests and imitate remote server response.

    session = None

    async def proxy_handler(req):
        if req.method == 'CONNECT':
            # Upgrade to HTTPS
            resp = web.StreamResponse()
            resp.content_length = 0
            await resp.prepare(req)
            await resp.write_eof()
            print("BEFORE_TLS")
            try:
                await req._start_tls(ssl_ctx)
            except Exception as exc:
                print(exc)
                raise
            print("CONNECT")
            return req

        print("PROXY SERVER", req.method, req.url)
        data = await req.read()
        headers = req.headers.copy()
        headers.pop(hdrs.HOST, None)
        proxy_auth = headers.pop(hdrs.PROXY_AUTHORIZATION, None)
        proxy_authenticate = headers.pop(hdrs.PROXY_AUTHORIZATION, None)
        assert proxy_auth is None
        assert proxy_authenticate is None

        async with session.request(
            req.method,
            req.rel_url,
            headers=headers,
            data=data
        ) as inner_resp:
            resp = web.StreamResponse(
                status=inner_resp.status,
                headers=inner_resp.headers
            )
            await resp.prepare(req)
            content = await inner_resp.read()
            await resp.write(content)
            await resp.write_eof()
            return resp

    async def run(app, *, ssl=False):
        nonlocal session
        if ssl:
            connector = aiohttp.TCPConnector(ssl=client_ssl_ctx)
            server_ssl = ssl_ctx
        else:
            connector = aiohttp.TCPConnector()
            server_ssl = None
        session = aiohttp.ClientSession(connector=connector)

        server = await aiohttp_server(app, ssl=server_ssl)
        remote_url = server.make_url('/')
        proxy_server = await aiohttp_raw_server(proxy_handler)
        proxy_url = proxy_server.make_url('/')

        print(f"proxy_url={proxy_url}, remote_url={remote_url}")
        return proxy_url, remote_url

    yield run

    if session is not None:
        loop.run_until_complete(session.close())


async def test_proxy_http_absolute_path(proxy_server) -> None:
    routes = web.RouteTableDef()

    @routes.get("/path")
    async def handler(req):
        assert req.path == "/path"
        assert req.query == {"query": "yes"}
        return web.Response(text="OK")

    app = web.Application()
    app.add_routes(routes)

    proxy_url, remote_url = await proxy_server(app)
    async with aiohttp.ClientSession() as client:
        async with client.get(
            (remote_url / "path").with_query(query="yes"),
            proxy=proxy_url
        ) as resp:
            assert resp.status == 200
            assert await resp.text() == "OK"


async def test_proxy_https_absolute_path(proxy_server, client_ssl_ctx) -> None:
    routes = web.RouteTableDef()

    @routes.get("/path")
    async def handler(req):
        assert req.path == "/path"
        assert req.query == {"query": "yes"}
        return web.Response(text="OK")

    app = web.Application()
    app.add_routes(routes)

    proxy_url, remote_url = await proxy_server(app, ssl=True)
    connector = aiohttp.TCPConnector(ssl=client_ssl_ctx)
    async with aiohttp.ClientSession(connector=connector) as client:
        async with client.get(
            (remote_url / "path").with_query(query="yes"),
            proxy=proxy_url
        ) as resp:
            assert resp.status == 200
            assert await resp.text() == "OK"


async def xtest_proxy_http_raw_path(proxy_server, get_request) -> None:
    url = 'http://aiohttp.io:2561/space sheep?q=can:fly'
    raw_url = 'http://aiohttp.io:2561/space%20sheep?q=can:fly'
    proxy = await proxy_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == 'aiohttp.io:2561'
    assert proxy.request.path_qs == raw_url


async def xtest_proxy_http_idna_support(proxy_server, get_request) -> None:
    url = 'http://éé.com/'
    raw_url = 'http://xn--9caa.com/'
    proxy = await proxy_server()

    await get_request(url=url, proxy=proxy.url)

    assert proxy.request.host == 'xn--9caa.com'
    assert proxy.request.path_qs == raw_url


async def xtest_proxy_http_connection_error(get_request) -> None:
    url = 'http://aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ClientConnectorError):
        await get_request(url=url, proxy=proxy_url)


async def xtest_proxy_http_bad_response(proxy_server, get_request) -> None:
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()
    proxy.return_value = dict(
        status=502,
        headers={'Proxy-Agent': 'TestProxy'})

    resp = await get_request(url=url, proxy=proxy.url)

    assert resp.status == 502
    assert resp.headers['Proxy-Agent'] == 'TestProxy'


async def xtest_proxy_http_auth(proxy_server, get_request) -> None:
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()

    await get_request(url=url, proxy=proxy.url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    auth = aiohttp.BasicAuth('user', 'pass')
    await get_request(url=url, auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    await get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers

    await get_request(url=url, auth=auth,
                      proxy_auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers


async def xtest_proxy_http_auth_utf8(proxy_server, get_request) -> None:
    url = 'http://aiohttp.io/path'
    auth = aiohttp.BasicAuth('юзер', 'пасс', 'utf-8')
    proxy = await proxy_server()

    await get_request(url=url, auth=auth, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers


async def xtest_proxy_http_auth_from_url(proxy_server,
                                        get_request) -> None:
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()

    auth_url = URL(url).with_user('user').with_password('pass')
    await get_request(url=auth_url, proxy=proxy.url)

    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy_url = URL(proxy.url).with_user('user').with_password('pass')
    await get_request(url=url, proxy=proxy_url)

    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' in proxy.request.headers


async def xtest_proxy_http_acquired_cleanup(proxy_server, loop) -> None:
    url = 'http://aiohttp.io/path'

    conn = aiohttp.TCPConnector()
    sess = aiohttp.ClientSession(connector=conn)
    proxy = await proxy_server()

    assert 0 == len(conn._acquired)

    resp = await sess.get(url, proxy=proxy.url)
    assert resp.closed

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.skip('we need to reconsider how we test this')
async def xtest_proxy_http_acquired_cleanup_force(proxy_server,
                                                 loop) -> None:
    url = 'http://aiohttp.io/path'

    conn = aiohttp.TCPConnector(force_close=True)
    sess = aiohttp.ClientSession(connector=conn)
    proxy = await proxy_server()

    assert 0 == len(conn._acquired)

    async def request():
        resp = await sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        await resp.release()

    await request()

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.skip('we need to reconsider how we test this')
async def xtest_proxy_http_multi_conn_limit(proxy_server, loop) -> None:
    url = 'http://aiohttp.io/path'
    limit, multi_conn_num = 1, 5

    conn = aiohttp.TCPConnector(limit=limit)
    sess = aiohttp.ClientSession(connector=conn)
    proxy = await proxy_server()

    current_pid = None

    async def request(pid):
        # process requests only one by one
        nonlocal current_pid

        resp = await sess.get(url, proxy=proxy.url)

        current_pid = pid
        await asyncio.sleep(0.2)
        assert current_pid == pid

        await resp.release()
        return resp

    requests = [request(pid) for pid in range(multi_conn_num)]
    responses = await asyncio.gather(*requests)

    assert len(responses) == multi_conn_num
    assert set(resp.status for resp in responses) == {200}

    await sess.close()


@pytest.mark.xfail
async def xtest_proxy_https_connect(proxy_server, get_request):
    proxy = await proxy_server()
    url = 'https://www.google.com.ua/search?q=aiohttp proxy'

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'www.google.com.ua:443'
    assert connect.host == 'www.google.com.ua'

    assert proxy.request.host == 'www.google.com.ua'
    assert proxy.request.path_qs == '/search?q=aiohttp+proxy'


@pytest.mark.xfail
async def xtest_proxy_https_connect_with_port(proxy_server, get_request):
    proxy = await proxy_server()
    url = 'https://secure.aiohttp.io:2242/path'

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'secure.aiohttp.io:2242'
    assert connect.host == 'secure.aiohttp.io:2242'

    assert proxy.request.host == 'secure.aiohttp.io:2242'
    assert proxy.request.path_qs == '/path'


@pytest.mark.xfail
async def xtest_proxy_https_send_body(proxy_server, loop):
    sess = aiohttp.ClientSession()
    proxy = await proxy_server()
    proxy.return_value = {'status': 200, 'body': b'1'*(2**20)}
    url = 'https://www.google.com.ua/search?q=aiohttp proxy'

    resp = await sess.get(url, proxy=proxy.url)
    body = await resp.read()
    await resp.release()
    await sess.close()

    assert body == b'1'*(2**20)


@pytest.mark.xfail
async def xtest_proxy_https_idna_support(proxy_server, get_request):
    url = 'https://éé.com/'
    proxy = await proxy_server()

    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert connect.method == 'CONNECT'
    assert connect.path == 'xn--9caa.com:443'
    assert connect.host == 'xn--9caa.com'


async def xtest_proxy_https_connection_error(get_request) -> None:
    url = 'https://secure.aiohttp.io/path'
    proxy_url = 'http://localhost:2242/'

    with pytest.raises(aiohttp.ClientConnectorError):
        await get_request(url=url, proxy=proxy_url)


async def xtest_proxy_https_bad_response(proxy_server,
                                        get_request) -> None:
    url = 'https://secure.aiohttp.io/path'
    proxy = await proxy_server()
    proxy.return_value = dict(
        status=502,
        headers={'Proxy-Agent': 'TestProxy'})

    with pytest.raises(aiohttp.ClientHttpProxyError):
        await get_request(url=url, proxy=proxy.url)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'CONNECT'
    # The following check fails on MacOS
    # assert proxy.request.path == 'secure.aiohttp.io:443'


@pytest.mark.xfail
async def xtest_proxy_https_auth(proxy_server, get_request):
    url = 'https://secure.aiohttp.io/path'
    auth = aiohttp.BasicAuth('user', 'pass')

    proxy = await proxy_server()
    await get_request(url=url, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' not in connect.headers
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = await proxy_server()
    await get_request(url=url, auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' not in connect.headers
    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = await proxy_server()
    await get_request(url=url, proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' in connect.headers
    assert 'Authorization' not in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers

    proxy = await proxy_server()
    await get_request(url=url, auth=auth,
                      proxy_auth=auth, proxy=proxy.url)

    connect = proxy.requests_list[0]
    assert 'Authorization' not in connect.headers
    assert 'Proxy-Authorization' in connect.headers
    assert 'Authorization' in proxy.request.headers
    assert 'Proxy-Authorization' not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_https_acquired_cleanup(proxy_server, loop):
    url = 'https://secure.aiohttp.io/path'

    conn = aiohttp.TCPConnector()
    sess = aiohttp.ClientSession(connector=conn)
    proxy = await proxy_server()

    assert 0 == len(conn._acquired)

    async def request():
        resp = await sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        await resp.release()

    await request()

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.xfail
async def xtest_proxy_https_acquired_cleanup_force(proxy_server, loop):
    url = 'https://secure.aiohttp.io/path'

    conn = aiohttp.TCPConnector(force_close=True)
    sess = aiohttp.ClientSession(connector=conn)
    proxy = await proxy_server()

    assert 0 == len(conn._acquired)

    async def request():
        resp = await sess.get(url, proxy=proxy.url)

        assert 1 == len(conn._acquired)

        await resp.release()

    await request()

    assert 0 == len(conn._acquired)

    await sess.close()


@pytest.mark.xfail
async def xtest_proxy_https_multi_conn_limit(proxy_server, loop):
    url = 'https://secure.aiohttp.io/path'
    limit, multi_conn_num = 1, 5

    conn = aiohttp.TCPConnector(limit=limit)
    sess = aiohttp.ClientSession(connector=conn)
    proxy = await proxy_server()

    current_pid = None

    async def request(pid):
        # process requests only one by one
        nonlocal current_pid

        resp = await sess.get(url, proxy=proxy.url)

        current_pid = pid
        await asyncio.sleep(0.2)
        assert current_pid == pid

        await resp.release()
        return resp

    requests = [request(pid) for pid in range(multi_conn_num)]
    responses = await asyncio.gather(*requests)

    assert len(responses) == multi_conn_num
    assert set(resp.status for resp in responses) == {200}

    await sess.close()


original_is_file = pathlib.Path.is_file


def mock_is_file(self):
    # make real netrc file invisible in home dir
    if self.name in ['_netrc', '.netrc'] and self.parent == self.home():
        return False
    else:
        return original_is_file(self)


async def xtest_proxy_from_env_http(proxy_server,
                                   get_request, mocker) -> None:
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()
    mocker.patch.dict(os.environ, {'http_proxy': str(proxy.url)})
    mocker.patch('pathlib.Path.is_file', mock_is_file)

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


async def xtest_proxy_from_env_http_with_auth(proxy_server,
                                             get_request, mocker):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    mocker.patch.dict(os.environ, {'http_proxy':
                                   str(proxy.url
                                       .with_user(auth.login)
                                       .with_password(auth.password))})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert proxy.request.headers['Proxy-Authorization'] == auth.encode()


async def xtest_proxy_from_env_http_with_auth_from_netrc(
        proxy_server, get_request, tmp_path, mocker):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    netrc_file = tmp_path / 'test_netrc'
    netrc_file_data = 'machine 127.0.0.1 login %s password %s' % (
        auth.login, auth.password)
    with netrc_file.open('w') as f:
        f.write(netrc_file_data)
    mocker.patch.dict(os.environ, {'http_proxy': str(proxy.url),
                                   'NETRC': str(netrc_file)})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert proxy.request.headers['Proxy-Authorization'] == auth.encode()


async def xtest_proxy_from_env_http_without_auth_from_netrc(
        proxy_server, get_request, tmp_path, mocker):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    netrc_file = tmp_path / 'test_netrc'
    netrc_file_data = 'machine 127.0.0.2 login %s password %s' % (
        auth.login, auth.password)
    with netrc_file.open('w') as f:
        f.write(netrc_file_data)
    mocker.patch.dict(os.environ, {'http_proxy': str(proxy.url),
                                   'NETRC': str(netrc_file)})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


async def xtest_proxy_from_env_http_without_auth_from_wrong_netrc(
        proxy_server, get_request, tmp_path, mocker):
    url = 'http://aiohttp.io/path'
    proxy = await proxy_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    netrc_file = tmp_path / 'test_netrc'
    invalid_data = 'machine 127.0.0.1 %s pass %s' % (
        auth.login, auth.password)
    with netrc_file.open('w') as f:
        f.write(invalid_data)

    mocker.patch.dict(os.environ, {'http_proxy': str(proxy.url),
                                   'NETRC': str(netrc_file)})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 1
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'http://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_from_env_https(proxy_server, get_request, mocker):
    url = 'https://aiohttp.io/path'
    proxy = await proxy_server()
    mocker.patch.dict(os.environ, {'https_proxy': str(proxy.url)})
    mock.patch('pathlib.Path.is_file', mock_is_file)

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 2
    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == 'https://aiohttp.io/path'
    assert 'Proxy-Authorization' not in proxy.request.headers


@pytest.mark.xfail
async def xtest_proxy_from_env_https_with_auth(proxy_server,
                                               get_request, mocker):
    url = 'https://aiohttp.io/path'
    proxy = await proxy_server()
    auth = aiohttp.BasicAuth('user', 'pass')
    mocker.patch.dict(os.environ, {'https_proxy':
                                   str(proxy.url
                                       .with_user(auth.login)
                                       .with_password(auth.password))})

    await get_request(url=url, trust_env=True)

    assert len(proxy.requests_list) == 2

    assert proxy.request.method == 'GET'
    assert proxy.request.host == 'aiohttp.io'
    assert proxy.request.path_qs == '/path'
    assert 'Proxy-Authorization' not in proxy.request.headers

    r2 = proxy.requests_list[0]
    assert r2.method == 'CONNECT'
    assert r2.host == 'aiohttp.io'
    assert r2.path_qs == '/path'
    assert r2.headers['Proxy-Authorization'] == auth.encode()


async def xtest_proxy_auth() -> None:
    async with aiohttp.ClientSession() as session:
        with pytest.raises(
                ValueError,
                match=r"proxy_auth must be None or BasicAuth\(\) tuple"):
            await session.get('http://python.org',
                              proxy='http://proxy.example.com',
                              proxy_auth=('user', 'pass'))
