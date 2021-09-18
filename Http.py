import socks
import socket
import re
import ssl
import time
from urllib.parse import urlparse


class Util(object):
    @staticmethod
    def header_dict2str(headers_dict):
        r = ""
        for k, v in headers_dict.items():
            if k.upper() == 'HOST':
                continue
            r += "%s: %s\r\n" % (k, v)
        return r

    @staticmethod
    def header_str2dict(headers_str):
        r = {}
        c = ""
        for i in headers_str.split('\n'):
            if ':' not in i:
                continue
            _i_s = i.strip().split(':', 1)
            if _i_s[0].strip().lower().startswith('set-cookie'):
                c += "%s, " % _i_s[1].strip()
            else:
                r.update({_i_s[0].strip(): _i_s[1].strip()})
        if c.__len__() > 0:
            r.update({'Set-Cookie': c.strip().rstrip(',')})
        return r

    @staticmethod
    def cookie_dict2str(cookie_dict):
        r = ""
        for k, v in cookie_dict.items():
            r += "%s=%s; " % (k, v)
        return r.strip().rstrip(';')


class Response(object):
    def __init__(self, raw, encoding='utf-8'):
        self.raw = raw
        self.encoding = encoding

    def __separate(self):
        return self.raw.partition(b'\r\n\r\n')

    @property
    def title(self):
        comp = re.findall(r"<title.*?>(.+?)</title>", self.text)
        if comp.__len__() > 0:
            return comp[0]
        return ""

    @property
    def status_code(self):
        s = self.__separate()[0].decode(self.encoding, errors='replace')
        if not s.startswith('HTTP/1.1'):
            return False
        code = s.split('\n')[0].replace('HTTP/1.1', '').strip().split(' ')[0].strip()
        if not code.isdigit():
            return False
        return int(code)

    @property
    def headers(self):
        s = self.__separate()[0].decode(self.encoding, errors='replace')
        return Util.header_str2dict(s)

    @property
    def cookies(self):
        s = self.__separate()[0].decode(self.encoding, errors='replace')
        d = {}
        for i in s.split('\n'):
            _i_s = i.strip().split(':', 1)
            if _i_s[0].strip().lower().startswith('set-cookie'):
                kv = _i_s[1].strip().split(';', 1)[0].strip()
                if '=' not in kv:
                    continue
                d.update({kv.split('=')[0].strip(): kv.split('=')[1].strip()})
        return d

    @property
    def body(self):
        s = self.__separate()
        return s[2] if len(s) > 1 else ""

    @property
    def text(self):
        return self.body.decode(self.encoding, errors='replace')


class Http(object):
    encoding = 'utf-8'
    BUFF_SIZE = 1024
    Util = Util
    default_timeout = 5

    @staticmethod
    def payload(method, url, headers, data=None):
        up = urlparse(url)
        _p = up.path if up.path else '/'
        if method == 'POST' and data is not None:
            headers.update({'Content-Length': str(len(data))})
        _h = Util.header_dict2str(headers) if headers else ""
        payload = str("%s %s HTTP/1.1\r\nHost: %s\r\n%s\r\n" % (method, _p, up.netloc, _h))
        if method == 'POST' and data is not None:
            payload += data
        return payload.encode(Http.encoding)

    @staticmethod
    def init_socket(s, url, ip=None, proxies=None, timeout=default_timeout):
        s.settimeout(timeout)
        if proxies is not None:
            s.set_proxy(proxy_type=proxies.type, addr=proxies.addr, port=proxies.port)
        port = 443 if urlparse(url).scheme == "https" else 80
        s.connect((urlparse(url).netloc, port)) if ip is None else s.connect((ip, port))
        if urlparse(url).scheme == "https":
            ctx = ssl.SSLContext()
            s = ctx.wrap_socket(s, server_hostname=urlparse(url).netloc)
        return s

    @staticmethod
    def sniff_data(ss):
        raw = b''
        t_start = time.time()
        while True:
            if time.time() - t_start > 30:
                raise TimeoutError
            try:
                packet = ss.recv(Http.BUFF_SIZE)
            except OSError:
                break
            raw += packet
            if packet.endswith(b'\r\n0\r\n\r\n') or packet == b'':
                break
        return raw

    @staticmethod
    def request(method, url, data=None, ip=None, headers=None, proxies=None, timeout=default_timeout):
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s = Http.init_socket(s, url=url, ip=ip, proxies=proxies, timeout=timeout)
            s.send(Http.payload(method, url=url, headers=headers, data=data))
        except OSError:
            s.close()
            raise
        raw = Http.sniff_data(s)
        s.close()
        return Response(raw, Http.encoding)

    @staticmethod
    def get(url, ip=None, headers=None, proxies=None, timeout=default_timeout):
        return Http.request('GET', url=url, ip=ip, headers=headers, proxies=proxies, timeout=timeout)

    @staticmethod
    def post(url, data, ip=None, headers=None, proxies=None, timeout=default_timeout):
        return Http.request('POST', url=url, data=data, ip=ip, headers=headers, proxies=proxies, timeout=timeout)

    @staticmethod
    def head(url, ip=None, headers=None, proxies=None, timeout=default_timeout):
        return Http.request('HEAD', url=url, ip=ip, headers=headers, proxies=proxies, timeout=timeout)

    @staticmethod
    def options(url, ip=None, headers=None, proxies=None, timeout=default_timeout):
        return Http.request('OPTIONS', url=url, ip=ip, headers=headers, proxies=proxies, timeout=timeout)
