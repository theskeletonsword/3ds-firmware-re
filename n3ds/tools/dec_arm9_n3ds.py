#!/usr/bin/env python3
"""Decrypt the ARM9 section of an N3DS FIRM (arm9loader header + AES-CTR @0x800).
Tries key combinations from aes_keys.txt and validates by entropy / ARM opcode patterns.
Found working for NATIVE_FIRM (K9L2 header): keyslot16 normal key = scramble(slot0x16KeyX, header KeyY@0x10), CTR = header@0x20 as-is.
usage: dec_arm9_n3ds.py firm_section2.bin out.bin"""
import sys, os, itertools, math, collections, re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
keys={}
for l in open(next(p for p in ('/home/skels/3ds-reversing/aes_keys.txt','/home/skels/3ds-reversing/o3ds/aes_keys.txt') if __import__('os').path.exists(p))):
    m=re.match(r'(\w+)=([0-9a-fA-F]{32})$',l.strip())
    if m: keys[m.group(1)]=bytes.fromhex(m.group(2))
C=keys['generatorConstant']
def rol(b,n):
    v=int.from_bytes(b,'big'); n%=128
    return (((v<<n)|(v>>(128-n)))&(2**128-1)).to_bytes(16,'big')
def scramble(x,y):
    v=int.from_bytes(rol(x,2),'big')^int.from_bytes(y,'big')
    v=(v+int.from_bytes(C,'big'))&(2**128-1)
    return rol(v.to_bytes(16,'big'),87)
def ecb_dec(k,d): c=Cipher(algorithms.AES(k),modes.ECB()).decryptor(); return c.update(d)
def ctr_dec(k,iv,d): c=Cipher(algorithms.AES(k),modes.CTR(iv)).decryptor(); return c.update(d)
def ent(c):
    cn=collections.Counter(c); return -sum(v/len(c)*math.log2(v/len(c)) for v in cn.values())
def score(p):
    # ARM: share of instructions with condition 0xE (AL)
    w=[int.from_bytes(p[i:i+4],'little')>>28 for i in range(0,len(p)-3,4)]
    return sum(1 for x in w if x==0xE)/len(w)
if __name__=='__main__':
    d=open(sys.argv[1],'rb').read()
    h=d[:0x200]
    size=int(h[0x30:0x38].split(b'\0')[0])
    magic=h[0x50:0x54]; print('magic',magic,'size',size)
    n11=keys['slot0x11KeyN']
    # Known working schemes (found by search, validated by ARM opcode statistics):
    #  NATIVE_FIRM (K9L2, system 11.x+): KeyX = slot0x16KeyX, KeyY = header[0x10:0x20] raw, CTR = header[0x20:0x30] raw
    #  SAFE_MODE_FIRM (no K9L magic, older arm9loader): KeyX = slot0x15KeyX, KeyY/CTR raw
    schemes={'K9L2/slot0x16':keys['slot0x16KeyX'],'old/slot0x15':keys['slot0x15KeyX']}
    best=None
    for name,kx in schemes.items():
        k=scramble(kx,h[0x10:0x20]); p=ctr_dec(k,h[0x20:0x30],d[0x800:0x800+0x4000]); sc=-ent(p)   # decrypted code has entropy well below 8 bits/byte
        print(name,'entropy',round(-sc,2),'ARM-cond-AL share',round(score(p),3))
        if best is None or sc>best[0]: best=(sc,name,k)
    if -best[0]>7.0: sys.exit('no working scheme')
    print('scheme',best[1])
    if len(sys.argv)>2:
        out=sys.argv[2]; base=os.path.dirname(out) or '.'
        dec=ctr_dec(best[2],h[0x20:0x30],d[0x800:0x800+size])
        open(out,'wb').write(dec)
        open(os.path.join(base,'arm9_header_0x800.bin'),'wb').write(d[:0x800])
        open(os.path.join(base,'arm9loader_tail.bin'),'wb').write(d[0x800+size:])
        print('written',out,len(dec))
