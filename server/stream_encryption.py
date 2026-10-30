"""Versioned bounded frames using Fernet, authenticated file ID, sequence and EOF.

No new cryptographic primitive: each frame is a full authenticated Fernet token.
File IDs prevent mixing files; sequence/terminal records prevent reorder/truncation.
"""
import io,os,struct
from cryptography.fernet import Fernet,InvalidToken
MAGIC=b'SFFRAME1\n'
CHUNK=1024*1024
MAX_TOKEN=2*1024*1024

def exact(handle,length):
    data=handle.read(length)
    if len(data)!=length: raise ValueError('Truncated encrypted stream')
    return data

class Writer:
    def __init__(self,handle,key):
        self.handle=handle;self.cipher=Fernet(key);self.file_id=os.urandom(16);self.sequence=0;self.buffer=bytearray();self.finished=False
        handle.write(MAGIC);self.frame(2,b'')
    def frame(self,flag,data):
        token=self.cipher.encrypt(self.file_id+struct.pack('>Q',self.sequence)+bytes([flag])+data)
        self.handle.write(struct.pack('>I',len(token)));self.handle.write(token);self.sequence+=1
    def write(self,data):
        if self.finished: raise ValueError('Stream finished')
        size=len(data)
        for offset in range(0,size,CHUNK):
            self.buffer.extend(data[offset:offset+CHUNK])
            while len(self.buffer)>=CHUNK:
                self.frame(0,bytes(self.buffer[:CHUNK]));del self.buffer[:CHUNK]
        return size
    def flush(self): self.handle.flush()
    def finish(self):
        if self.finished: raise ValueError('Already finished')
        if self.buffer: self.frame(0,bytes(self.buffer));self.buffer.clear()
        self.frame(1,b'');self.flush();self.finished=True

class Reader(io.RawIOBase):
    def __init__(self,handle,key):
        super().__init__();self.handle=handle;self.cipher=Fernet(key);self.sequence=0;self.buffer=b'';self.ended=False
        if exact(handle,len(MAGIC))!=MAGIC: raise ValueError('Unsupported encrypted stream')
        header=self.token()
        if len(header)!=25 or header[16:]!=b'\0'*8+b'\2': raise ValueError('Invalid encrypted header')
        self.file_id=header[:16];self.sequence=1
    def token(self):
        length=struct.unpack('>I',exact(self.handle,4))[0]
        if not 100<=length<=MAX_TOKEN: raise ValueError('Invalid frame size')
        return self.cipher.decrypt(exact(self.handle,length))
    def readable(self): return True
    def readinto(self,target):
        if not self.buffer and not self.ended:
            data=self.token()
            if len(data)<25 or data[:16]!=self.file_id or data[16:24]!=struct.pack('>Q',self.sequence): raise ValueError('Invalid frame sequence')
            self.sequence+=1;flag=data[24];payload=data[25:]
            if flag==1:
                if payload or self.handle.read(1): raise ValueError('Data after encrypted EOF')
                self.ended=True
            elif flag==0 and 0<len(payload)<=CHUNK: self.buffer=payload
            else: raise ValueError('Invalid frame')
        count=min(len(target),len(self.buffer));target[:count]=self.buffer[:count];self.buffer=self.buffer[count:];return count

def open_reader(handle,key): return io.BufferedReader(Reader(handle,key),buffer_size=65536)

def verify(path,key):
    import hashlib
    digest=hashlib.sha256();total=0
    with open(path,'rb') as raw,open_reader(raw,key) as reader:
        while block:=reader.read(CHUNK): digest.update(block);total+=len(block)
    return dict(plaintext_bytes=total,plaintext_sha256=digest.hexdigest())
