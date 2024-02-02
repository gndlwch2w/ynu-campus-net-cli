import os
from os import PathLike
import re
import platform
import time
import json
import hmac
import hashlib
import user_agents
from requests import Response
from typing import AnyStr, Any, Tuple

__all__ = [
    'get_timestamp',
    'get_ip_addr',
    'load_json',
    'md5',
    'sha1',
    'parse_user_agent',
    'Base64',
    'jsonp_to_json'
]

def get_timestamp() -> int:
    """Returns the current timestamp in milliseconds."""
    return int(time.time() * 1000)

def get_ip_addr(ethernet: str) -> str:
    """Returns the ipv4 address of the given ethernet."""
    system_name = platform.system().lower()
    if system_name == 'windows':
        r = os.popen('ipconfig').read().strip().split('\n')
        for i, line in enumerate(r):
            if line.strip().startswith(ethernet):
                r = next(filter(lambda e: e.strip().startswith('IPv4 Address'), r[i:]))
                return r.split(':')[1].strip()
        raise ValueError(f'Could not parse IPv4 address on {ethernet}')
    if system_name == 'darwin':
        r = os.popen('ifconfig').read().strip().split('\n')
        for i, line in enumerate(r):
            if line.strip().startswith(ethernet):
                r = next(filter(lambda e: e.split()[0] == 'inet', r[i:]))
                return r.split()[1].strip()
        raise ValueError(f'Could not parse IPv4 address on {ethernet}')
    raise NotImplementedError(f'Could not support system type of {system_name}')

def load_json(path: PathLike[AnyStr], encoding: str = 'utf-8') -> Any:
    """Deserializes the json file to a Python object."""
    with open(path, 'r', encoding=encoding) as fp:
        return json.load(fp)

def md5(s1: str, s2: str) -> str:
    """Returns a md5 hash of the string."""
    return hmac.new(s1.encode(), s2.encode(), hashlib.md5).hexdigest()

def sha1(s: str) -> str:
    """Returns a sha1 hash of the string."""
    return hashlib.sha1(s.encode()).hexdigest()

def parse_user_agent(user_agent: str) -> Tuple[str, str]:
    """Parses the user agent string to extract the device and platform."""
    ua = user_agents.parse(user_agent)
    device = ua.device.family if ua.device.family else 'Windows NT'
    platform = ua.os.family if ua.os.family else 'Windows'
    return device, platform

class Base64:
    """Base64 encoder with alpha."""

    def __init__(self, alpha: str):
        self.alpha = alpha
        self.pad = '='

    @staticmethod
    def _get_byte(s: AnyStr, i: AnyStr) -> AnyStr:
        x = ord(s[i])
        if x > 255:
            print('INVALID_CHARACTER_ERR: DOM Exception 5')
            exit(0)
        return x

    def encode(self, s: AnyStr) -> AnyStr:
        i, b10, x = 0, 0, []
        imax = len(s) - len(s) % 3
        if len(s) == 0:
            return s
        for i in range(0, imax, 3):
            b10 = ((self._get_byte(s, i) << 16) |
                   (self._get_byte(s, i + 1) << 8) |
                   self._get_byte(s, i + 2))
            x.append(self.alpha[(b10 >> 18)])
            x.append(self.alpha[((b10 >> 12) & 63)])
            x.append(self.alpha[((b10 >> 6) & 63)])
            x.append(self.alpha[(b10 & 63)])
        i = imax
        if len(s) - imax == 1:
            b10 = self._get_byte(s, i) << 16
            x.append(self.alpha[(b10 >> 18)] +
                     self.alpha[((b10 >> 12) & 63)] +
                     self.pad + self.pad)
        elif len(s) - imax == 2:
            b10 = (self._get_byte(s, i) << 16) | (self._get_byte(s, i + 1) << 8)
            x.append(self.alpha[(b10 >> 18)] +
                     self.alpha[((b10 >> 12) & 63)] +
                     self.alpha[((b10 >> 6) & 63)] + self.pad)
        return ''.join(x)

    def decode(self, s: AnyStr) -> AnyStr:
        raise NotImplementedError('decode')

def jsonp_to_json(response: Response, callback: str = '_', encoding: str = 'utf-8') -> Any:
    """Parse JSONP response to JSON response."""
    if response.status_code == 200:
        response.encoding = encoding
        return json.loads(re.match(f'{callback}\\((.*)\\)', response.text).group(1))
    raise ValueError(f'Could not parse ERR REQUESTS')
