"""Entry-point guard for the two reviewed, fixed-base SAI RU builds."""
import hashlib
import struct

APPROVED = {
    '8cffd484a3a38e9664042c6694e542893b4d1cb6d448a3dbe88caa9b74149085': 32,
    '886e1958414755ff86028dbedc37bb1a3de84c2c8e076d9cce32e8d6ede55ba2': 64,
}
MARKER = b'SAIRU-OFFLINE-GUARD-V1\0'

def align(n, a):
    return (n+a-1)//a*a

class PE:
    def __init__(self, data):
        self.data=data
        self.pe=struct.unpack_from('<I', data, 60)[0]
        if data[:2]!=b'MZ' or data[self.pe:self.pe+4]!=b'PE\0\0':
            raise ValueError('Invalid PE')
        self.opt=self.pe+24
        self.bits=64 if self.u16(self.opt)==0x20b else 32
        self.width=self.bits//8
        self.fmt='<Q' if self.bits==64 else '<I'
        self.base=struct.unpack_from(self.fmt,data,self.opt+(24 if self.bits==64 else 28))[0]
        self.directory=self.opt+(112 if self.bits==64 else 96)
        start=self.opt+self.u16(self.pe+20)
        self.sections=[]
        for i in range(self.u16(self.pe+6)):
            h=start+40*i
            name,vs,rva,size,raw=struct.unpack_from('<8sIIII',data,h)
            self.sections.append(dict(h=h,name=name,vs=vs,rva=rva,size=size,raw=raw))
    def u16(self,o):return struct.unpack_from('<H',self.data,o)[0]
    def u32(self,o):return struct.unpack_from('<I',self.data,o)[0]
    def offset(self,rva):
        for s in self.sections:
            if s['rva']<=rva<s['rva']+s['size']:return s['raw']+rva-s['rva']
        raise ValueError('Unmapped RVA')
    def imports(self):
        rva=self.u32(self.directory+8); o=self.offset(rva); result={}
        while self.u32(o+12):
            original,_,_,_,iat=struct.unpack_from('<5I',self.data,o)
            if not original:raise ValueError('Import lookup table is missing')
            p=self.offset(original); index=0
            while True:
                entry=struct.unpack_from(self.fmt,self.data,p+index*self.width)[0]
                if not entry:break
                if not entry & (1<<(self.bits-1)):
                    n=self.offset(entry)+2; end=self.data.index(b'\0',n)
                    name=self.data[n:end].decode('ascii')
                    result[name]=self.base+iat+index*self.width
                index+=1
            o+=20
        return result

class Code:
    def __init__(self,rva):self.data=bytearray();self.rva=rva;self.labels={};self.fixups=[]
    def emit(self,data):self.data.extend(data)
    def label(self,name):self.labels[name]=len(self.data)
    def branch(self,op,target):
        self.emit(op);self.fixups.append((len(self.data),target));self.emit(b'\0'*4)
    def finish(self):
        for offset,target in self.fixups:
            delta=(self.labels[target]-offset-4 if isinstance(target,str) else target-self.rva-offset-4)
            struct.pack_into('<i',self.data,offset,delta)
        return bytes(self.data)

def bootstrap(bits,base,rva,entry,imports,dllva,exportva):
    c=Code(rva)
    if bits==32:
        c.emit(b'\x9c\x60') # preserve flags and integer registers
        c.emit(b'\x68'+struct.pack('<I',dllva))
        c.emit(b'\xff\x15'+struct.pack('<I',imports['LoadLibraryW']))
        c.emit(b'\x85\xc0');c.branch(b'\x0f\x84','fail')
        c.emit(b'\x68'+struct.pack('<I',exportva)+b'\x50')
        c.emit(b'\xff\x15'+struct.pack('<I',imports['GetProcAddress']))
        c.emit(b'\x85\xc0');c.branch(b'\x0f\x84','fail')
        c.emit(b'\xff\xd0\x85\xc0');c.branch(b'\x0f\x84','fail')
        c.emit(b'\x61\x9d');c.branch(b'\xe9',entry)
        c.label('fail');c.emit(b'\x6a\x01\xff\x15'+struct.pack('<I',imports['ExitProcess'])+b'\xcc')
    else:
        c.emit(b'\x9c\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53')
        # Windows x64: 32-byte shadow space, six XMM saves, alignment padding.
        c.emit(b'\x48\x81\xec\x88\x00\x00\x00')
        for i in range(6):c.emit(b'\xf3\x0f\x7f'+bytes([0x44+8*i,0x24,0x20+16*i]))
        c.emit(b'\x48\xb9'+struct.pack('<Q',dllva))
        c.emit(b'\x48\xb8'+struct.pack('<Q',imports['LoadLibraryW'])+b'\xff\x10')
        c.emit(b'\x48\x85\xc0');c.branch(b'\x0f\x84','fail')
        c.emit(b'\x48\x89\xc1\x48\xba'+struct.pack('<Q',exportva))
        c.emit(b'\x48\xb8'+struct.pack('<Q',imports['GetProcAddress'])+b'\xff\x10')
        c.emit(b'\x48\x85\xc0');c.branch(b'\x0f\x84','fail')
        c.emit(b'\xff\xd0\x85\xc0');c.branch(b'\x0f\x84','fail')
        for i in range(6):c.emit(b'\xf3\x0f\x6f'+bytes([0x44+8*i,0x24,0x20+16*i]))
        c.emit(b'\x48\x81\xc4\x88\x00\x00\x00\x41\x5b\x41\x5a\x41\x59\x41\x58\x5a\x59\x58\x9d')
        c.branch(b'\xe9',entry)
        c.label('fail');c.emit(b'\xb9\x01\x00\x00\x00')
        c.emit(b'\x48\xb8'+struct.pack('<Q',imports['ExitProcess'])+b'\xff\x10\xcc')
    return c.finish()

def checksum(data,offset):
    struct.pack_into('<I',data,offset,0); total=0
    for i in range(0,len(data),2):
        total+=int.from_bytes(data[i:i+2],'little');total=(total&65535)+(total>>16)
    total=(total&65535)+(total>>16)
    struct.pack_into('<I',data,offset,total+len(data))

def protect(original):
    digest=hashlib.sha256(original).hexdigest()
    if digest not in APPROVED:raise ValueError('Неизвестная или уже защищённая EXE. Исходный файл не изменён.')
    p=PE(original)
    if p.bits!=APPROVED[digest]:raise ValueError('Architecture mismatch')
    if p.u16(p.opt+70)&0x40:raise ValueError('Only reviewed fixed-base images are supported')
    if p.u32(p.directory+32):raise ValueError('Refusing to alter a signed PE')
    s=max(p.sections,key=lambda s:s['raw'])
    if len(original)!=s['raw']+s['size'] or s!=max(p.sections,key=lambda s:s['rva']):
        raise ValueError('Unexpected section layout/overlay')
    imports=p.imports()
    for name in ('LoadLibraryW','GetProcAddress','ExitProcess'):
        if name not in imports:raise ValueError('Missing import '+name)
    data=bytearray(original);data.extend(MARKER)
    def current_rva():return s['rva']+len(data)-s['raw']
    if len(data)%2:data.append(0)
    dllva=p.base+current_rva();data.extend('SAI2RuLicense.dll\0'.encode('utf-16le'))
    exportva=p.base+current_rva();data.extend(b'CheckLicense\0')
    data.extend(b'\0'*(align(len(data),16)-len(data)))
    entry=current_rva()
    code=bootstrap(p.bits,p.base,entry,p.u32(p.opt+16),imports,dllva,exportva)
    data.extend(code)
    vs=len(data)-s['raw'];data.extend(b'\0'*(align(len(data),p.u32(p.opt+36))-len(data)))
    rawsize=len(data)-s['raw']
    struct.pack_into('<I',data,s['h']+8,vs)
    struct.pack_into('<I',data,s['h']+16,rawsize)
    struct.pack_into('<I',data,s['h']+36,(p.u32(s['h']+36)|0x60000020)&~0x02000000)
    struct.pack_into('<I',data,p.opt+16,entry)
    struct.pack_into('<I',data,p.opt+56,align(s['rva']+vs,p.u32(p.opt+32)))
    struct.pack_into('<I',data,p.opt+8,p.u32(p.opt+8)+rawsize-s['size'])
    checksum(data,p.opt+64)
    for section in p.sections:
        start,length=section['raw'],section['size']
        if data[start:start+length]!=original[start:start+length]:raise ValueError('Original section changed')
    return bytes(data)
