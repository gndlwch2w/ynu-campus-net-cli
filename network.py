import math
import argparse
import requests
import json
from easydict import EasyDict
from typing import Sized, Callable
from utils import (
    get_ip_addr,
    get_timestamp,
    load_json,
    md5,
    sha1,
    Base64,
    jsonp_to_json,
    parse_user_agent)

default_config = {
    'user': {
        'username': '',
        'password': ''
    },
    'device': {
        'ethernet': 'Wireless LAN adapter WLAN',
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    },
    'api': {
        'authenticate': 'http://202.203.208.5/cgi-bin/srun_portal',
        'challenge': 'http://202.203.208.5/cgi-bin/get_challenge'
    },
    'constant': {
        'type': '1',
        'n': '200',
        'enc': 'srun_bx1',
        'ac_id': '0',
        'domain': '',
        'alpha': 'LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA'
    }
}

def encode_user_info(info: str, token: str) -> str:
    """Encode the user information with the given token."""
    def ordat(msg, idx):
        if len(msg) > idx: return ord(msg[idx])
        return 0

    def sencode(msg, key):
        l, pwd = len(msg), []
        for i in range(0, l, 4):
            pwd.append(ordat(msg, i) |
                       ordat(msg, i + 1) << 8 |
                       ordat(msg, i + 2) << 16 |
                       ordat(msg, i + 3) << 24)
        if key: pwd.append(l)
        return pwd

    def lencode(msg, key):
        l, ll = len(msg), (len(msg) - 1) << 2
        if key:
            m = msg[l - 1]
            if m < ll - 3 or m > ll: return
            ll = m
        for i in range(0, l):
            msg[i] = (chr(msg[i] & 0xff) +
                      chr(msg[i] >> 8 & 0xff) +
                      chr(msg[i] >> 16 & 0xff) +
                      chr(msg[i] >> 24 & 0xff))
        if key: return ''.join(msg)[0:ll]
        return ''.join(msg)

    if info == '': return ''
    pwd, pwdk = sencode(info, True), sencode(token, False)
    if len(pwdk) < 4: pwdk = pwdk + [0] * (4 - len(pwdk))
    n = len(pwd) - 1
    z = pwd[n]
    c = 0x86014019 | 0x183639A0
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while 0 < q:
        d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3
        p = 0
        while p < n:
            y = pwd[p + 1]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
            z = pwd[p]
            p = p + 1
        y = pwd[0]
        m = z >> 5 ^ y << 2
        m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
        m = m + (pwdk[(p & 3) ^ e] ^ z)
        pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
        z = pwd[n]
        q = q - 1
    return lencode(pwd, False)

# noinspection PyUnresolvedReferences
def authenticate(config: EasyDict, callback: Callable):
    # noinspection PyUnresolvedReferences
    def get_challenge(username: str, ip: str, callback: Callable) -> str:
        params = {
            'callback': '_',
            'username': username,
            'ip': ip,
            '_': get_timestamp()
        }
        return callback(requests.get(config.api.challenge, params=params))

    username = config.user.username + config.constant.domain
    ip = get_ip_addr(config.device.ethernet)
    token = get_challenge(username, ip, callback=jsonp_to_json)['challenge']
    hmd5 = md5(config.user.password, token)
    base64 = Base64(config.constant.alpha)
    device, platform = parse_user_agent(config.device.user_agent)

    info = {
        'username': username,
        'password': config.user.password,
        'ip': ip,
        'acid': config.constant.ac_id,
        'enc_ver': config.constant.enc
    }

    i = encode_user_info(json.dumps(info), token)
    i = '{SRBX1}' + base64.encode(i)
    chk_str = token + username
    chk_str += token + hmd5
    chk_str += token + config.constant.ac_id
    chk_str += token + ip
    chk_str += token + config.constant.n
    chk_str += token + config.constant.type
    chk_str += token + i
    chk_sum = sha1(chk_str)

    params = {
        'callback': '_',
        'action': 'login',
        'username': username,
        'password': '{MD5}' + hmd5,
        'ac_id': config.constant.ac_id,
        'ip': ip,
        'chksum': chk_sum,
        'info': i,
        'n': config.constant.n,
        'type': config.constant.type,
        'os': device,
        'name': platform,
        'double_stack': 0,
        '_': get_timestamp()
    }
    return callback(requests.get(config.api.authenticate, params=params))

# noinspection PyUnresolvedReferences
def main(opt):
    def is_valid(s):
        if s is None: return False
        if isinstance(s, str): return len(s.strip()) != 0
        if isinstance(s, Sized): return len(s) != 0
        return True

    config = None
    if is_valid(opt.config):
        config = load_json(opt.config)
    config = EasyDict(config or default_config.copy())
    config.user.username = opt.username or config.user.username
    assert is_valid(config.user.username), 'Username cannot be empty'
    config.user.password = opt.password or config.user.password
    assert is_valid(config.user.password), 'Password cannot be empty'
    print(authenticate(config, jsonp_to_json)['suc_msg'])

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--username', type=str, default='')
    parser.add_argument('-p', '--password', type=str, default='')
    parser.add_argument('--config', type=str, default='')
    main(parser.parse_args())
