#!/usr/bin/env python3
"""Low-frequency TLS ServerHello prober (read-only).
Usage: python3 tlsprobe.py <host> <port> <sni> <mode>
  mode: tls13 | tls13-cipherpref | tls12
Captures ServerHello: version, cipher, extension order; plus post-handshake flight.
"""
import socket, struct, os, sys, time

EXT_NAMES = {0:'server_name',5:'status_request',10:'supported_groups',11:'ec_point_formats',
 13:'signature_algorithms',14:'srp',16:'alpn',18:'signed_cert_timestamp',21:'padding',
 23:'extended_master_secret',27:'compress_certificate',35:'session_ticket',43:'supported_versions',
 45:'psk_key_exchange_modes',51:'key_share',65281:'renegotiation_info'}
CIPHER_NAMES = {0x1301:'TLS_AES_128_GCM_SHA256',0x1302:'TLS_AES_256_GCM_SHA384',
 0x1303:'TLS_CHACHA20_POLY1305_SHA256',0xc02b:'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
 0xc02f:'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',0xc02c:'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
 0xc030:'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',0xcca9:'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305',
 0xcca8:'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',0x009c:'TLS_RSA_WITH_AES_128_GCM_SHA256',
 0x009d:'TLS_RSA_WITH_AES_256_GCM_SHA384'}
HS_NAMES = {1:'ClientHello',2:'ServerHello',4:'NewSessionTicket',11:'Certificate',12:'ServerKeyExchange',
 13:'CertificateRequest',14:'ServerHelloDone',15:'CertificateVerify',16:'ClientKeyExchange',20:'Finished',22:'CertificateStatus'}
ALERT_DESC = {0:'close_notify',10:'unexpected_message',20:'bad_record_mac',40:'handshake_failure',42:'bad_certificate',
 43:'unsupported_certificate',44:'certificate_revoked',45:'certificate_expired',46:'certificate_unknown',
 47:'illegal_parameter',70:'protocol_version',71:'insufficient_security',80:'internal_error',86:'inappropriate_fallback',90:'user_canceled',109:'missing_extension',112:'unsupported_extension'}
HRR_MAGIC = bytes.fromhex('CF21AD74E59A6111BE1D8C021E65B891C2A211167AA94CAA0CCF')

def u16(b): return struct.unpack('!H', b)[0]
def ext(t, data): return struct.pack('!HH', t, len(data)) + data
def sni_ext(host):
    h = host.encode(); e = b'\x00' + struct.pack('!H', len(h)) + h
    return ext(0, struct.pack('!H', len(e)) + e)
def alpn_ext(ps):
    d = b''.join(bytes([len(p)]) + p.encode() for p in ps)
    return ext(16, struct.pack('!H', len(d)) + d)
def groups_ext(gs): return ext(10, struct.pack('!H', 2*len(gs)) + b''.join(struct.pack('!H', g) for g in gs))
def sigalgs_ext(aa): return ext(13, struct.pack('!H', 2*len(aa)) + b''.join(struct.pack('!H', a) for a in aa))
def sv_ext(vv): return ext(43, bytes([2*len(vv)]) + b''.join(struct.pack('!H', v) for v in vv))
def ks_ext(shares):
    e = b''.join(struct.pack('!H', g) + struct.pack('!H', len(kx)) + kx for g, kx in shares)
    return ext(51, struct.pack('!H', len(e)) + e)

def client_hello(host, ciphers, extensions):
    body = struct.pack('!H', 0x0303) + os.urandom(32) + b'\x00'
    body += struct.pack('!H', 2*len(ciphers)) + b''.join(struct.pack('!H', c) for c in ciphers)
    body += b'\x01\x00'
    e = b''.join(extensions)
    body += struct.pack('!H', len(e)) + e
    hs = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('!H', len(hs)) + hs

def x25519_share():
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    k = X25519PrivateKey.generate()
    return (29, k.public_key().public_bytes_raw())

def read_record(f):
    hdr = f.read(5)
    if len(hdr) < 5: return None, None
    typ, ver, ln = hdr[0], u16(hdr[1:3]), u16(hdr[3:5])
    data = b''
    while len(data) < ln:
        chunk = f.read(ln - len(data))
        if not chunk: break
        data += chunk
    return (typ, ver, data)

def parse_server_hello(hs):
    assert hs[0] == 2
    ver = u16(hs[4:6]); rnd = hs[6:38]
    sl = hs[38]; sid = hs[39:39+sl]; off = 39 + sl
    cipher = u16(hs[off:off+2]); off += 3
    et = u16(hs[off:off+2]); off += 2; end = off + et
    exts = []
    while off < end:
        t, l = u16(hs[off:off+2]), u16(hs[off+2:off+4])
        exts.append((t, hs[off+4:off+4+l])); off += 4 + l
    return ver, rnd, sid, cipher, exts

def fmt_ext(t, v):
    n = EXT_NAMES.get(t, f'unknown({t})')
    extra = ''
    if t == 43 and len(v) >= 2: extra = '=%s' % ','.join('0x%04x' % u16(v[i:i+2]) for i in range(0, len(v), 2))
    if t == 51 and len(v) >= 2: extra = '=group %d' % u16(v[:2])
    return f'{t}({n}){extra}'

def main():
    host, port, sni, mode = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    sigalgs = [0x0403,0x0804,0x0401,0x0503,0x0805,0x0501,0x0601,0x0603]
    if mode == 'tls13':
        ciphers = [0x1301, 0x1302, 0x1303]
        exts = [sni_ext(sni), groups_ext([29,23,24]), sigalgs_ext(sigalgs), alpn_ext(['h2','http/1.1']),
                ext(5, b'\x01\x00\x00\x00\x00'), sv_ext([0x0304]), ext(45, b'\x01\x01'), ks_ext([x25519_share()])]
    elif mode == 'tls13-cipherpref':
        ciphers = [0x1302, 0x1303, 0x1301]  # client order: 256, chacha, 128
        exts = [sni_ext(sni), groups_ext([29,23,24]), sigalgs_ext(sigalgs),
                sv_ext([0x0304]), ext(45, b'\x01\x01'), ks_ext([x25519_share()])]
    elif mode == 'tls12':
        ciphers = [0xc030, 0xcca8, 0xc02f, 0x009d, 0x009c]  # client order: 256 first
        exts = [sni_ext(sni), ext(11, b'\x01\x00'), groups_ext([29,23,24]), ext(35, b''),
                sigalgs_ext(sigalgs), ext(5, b'\x01\x00\x00\x00\x00'), alpn_ext(['h2','http/1.1']),
                ext(23, b''), ext(65281, b'\x00')]
    else:
        sys.exit('bad mode')

    s = socket.create_connection((host, port), timeout=10)
    f = s.makefile('rb')
    s.sendall(client_hello(sni, ciphers, exts))
    print(f'=== {host}:{port} SNI={sni} mode={mode} ===')
    hs_buf = b''
    deadline = time.time() + 4
    hs_types = []
    got_sh = False
    post_records = []
    try:
        while time.time() < deadline:
            s.settimeout(max(0.1, deadline - time.time()))
            r = read_record(f)
            if r[0] is None: break
            typ, ver, data = r
            if typ == 21:
                print(f'ALERT level={data[0]} desc={data[1]} ({ALERT_DESC.get(data[1],"?" )})')
                break
            if typ == 20:
                print('ChangeCipherSpec'); continue
            if typ == 22:
                off = 0
                while off + 4 <= len(data):
                    ht, hl = data[off], int.from_bytes(data[off+1:off+4], 'big')
                    body = data[off+4:off+4+hl]
                    hs_types.append((ht, hl))
                    if ht == 2 and not got_sh:
                        got_sh = True
                        ver2, rnd, sid, cipher, sexts = parse_server_hello(data[off:off+4+hl])
                        is_hrr = rnd == HRR_MAGIC
                        print(('HelloRetryRequest' if is_hrr else 'ServerHello') +
                              f' legacy_ver=0x{ver2:04x} cipher=0x{cipher:04x} ({CIPHER_NAMES.get(cipher,"?")}) session_id_len={len(sid)}')
                        print('  extensions in order: ' + ' '.join(fmt_ext(t, v) for t, v in sexts))
                    off += 4 + hl
                if mode == 'tls12' and any(t == 14 for t, _ in hs_types):
                    break
                continue
            if typ == 23:
                post_records.append(len(data))
                continue
            print(f'record type={typ} len={len(data)}')
    except socket.timeout:
        pass
    except Exception as e:
        print('read err:', e)
    print('handshake flight:', ' '.join(f'{HS_NAMES.get(t,"?"+str(t))}[{l}]' for t, l in hs_types))
    if post_records:
        print(f'post-handshake appdata records from server: count={len(post_records)} lens={post_records}')
    s.close()

if __name__ == '__main__':
    main()
