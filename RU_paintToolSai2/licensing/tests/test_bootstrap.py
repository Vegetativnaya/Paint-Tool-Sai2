"""CPU-level tests of both entry stubs with simulated Windows API calls."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from pe_guard import bootstrap
try:
    import unicorn
    from unicorn import x86_const as reg
except ImportError:
    unicorn=None

@unittest.skipUnless(unicorn,'Install requirements-test.txt for CPU emulation checks')
class BootstrapTests(unittest.TestCase):
    def test_32_and_64_bit_gate_and_register_preservation(self):
        for bits in (32,64):
            for scenario in ('valid','invalid','missing-dll','missing-export'):
                with self.subTest(bits=bits,scenario=scenario):self.run_stub(bits,scenario)

    def run_stub(self,bits,scenario):
        cpu=unicorn.Uc(unicorn.UC_ARCH_X86,unicorn.UC_MODE_64 if bits==64 else unicorn.UC_MODE_32)
        base=0x400000;stack=0x700000;cpu.mem_map(base,0x10000);cpu.mem_map(stack,0x10000)
        addresses=dict(load=base+0x4000,get=base+0x4100,check=base+0x4200,exit=base+0x4300)
        width=bits//8;fmt='<Q' if bits==64 else '<I'
        imports={name:base+0x3000+i*width for i,name in enumerate(('LoadLibraryW','GetProcAddress','ExitProcess'))}
        for name,target in [('LoadLibraryW','load'),('GetProcAddress','get'),('ExitProcess','exit')]:
            cpu.mem_write(imports[name],struct.pack(fmt,addresses[target]))
        for name,target in addresses.items():
            instruction=b'\xc3'
            if bits==32 and name in ('load','get'):instruction=b'\xc2'+struct.pack('<H',4 if name=='load' else 8)
            cpu.mem_write(target,instruction)
        dll=base+0x5000;export=base+0x5100
        code=bootstrap(bits,base,0x1000,0x2000,imports,dll,export)
        cpu.mem_write(base+0x1000,code)
        names=(['RAX','RBX','RCX','RDX','RSI','RDI','RBP','R8','R9','R10','R11','R12','R13','R14','R15'] if bits==64
               else ['EAX','EBX','ECX','EDX','ESI','EDI','EBP'])
        initial={getattr(reg,'UC_X86_REG_'+name):0x123400+17*i for i,name in enumerate(names)}
        for register,value in initial.items():cpu.reg_write(register,value)
        sp=reg.UC_X86_REG_RSP if bits==64 else reg.UC_X86_REG_ESP
        ax=reg.UC_X86_REG_RAX if bits==64 else reg.UC_X86_REG_EAX
        initial_sp=stack+0x8008 if bits==64 else stack+0x8000
        cpu.reg_write(sp,initial_sp);cpu.reg_write(reg.UC_X86_REG_EFLAGS,0x202)
        xmm={getattr(reg,'UC_X86_REG_XMM'+str(i)):0x11111111111111112222222222222222+i for i in range(6)}
        if bits==64:
            for register,value in xmm.items():cpu.reg_write(register,value)
        started=[];exited=[];calls=[]
        def argument(index):
            if bits==64:return cpu.reg_read(reg.UC_X86_REG_RCX if index==0 else reg.UC_X86_REG_RDX)
            return struct.unpack('<I',cpu.mem_read(cpu.reg_read(sp)+4+4*index,4))[0]
        def hook(uc,address,size,user):
            if address==base+0x2000:
                started.append(True);uc.emu_stop();return
            if address not in addresses.values():return
            if bits==64:self.assertEqual(uc.reg_read(sp)%16,8,'Windows x64 stack must be aligned at call boundary')
            calls.append(address)
            if address==addresses['load']:
                self.assertEqual(argument(0),dll)
                uc.reg_write(ax,0 if scenario=='missing-dll' else 0x12345)
            elif address==addresses['get']:
                self.assertEqual(argument(0),0x12345);self.assertEqual(argument(1),export)
                uc.reg_write(ax,0 if scenario=='missing-export' else addresses['check'])
            elif address==addresses['check']:
                for name in (['RCX','RDX','R8','R9','R10','R11'] if bits==64 else ['ECX','EDX']):
                    uc.reg_write(getattr(reg,'UC_X86_REG_'+name),0xdeadbeef)
                if bits==64:
                    for register in xmm:uc.reg_write(register,0xffffffffffffffffffffffffffffffff)
                uc.reg_write(ax,0 if scenario=='invalid' else 1)
            else:
                exited.append(argument(0));uc.emu_stop()
        cpu.hook_add(unicorn.UC_HOOK_CODE,hook)
        cpu.emu_start(base+0x1000,base+0x10000,count=1000)
        if scenario=='valid':
            self.assertEqual(started,[True]);self.assertEqual(exited,[])
            for register,value in initial.items():self.assertEqual(cpu.reg_read(register),value)
            self.assertEqual(cpu.reg_read(sp),initial_sp)
            self.assertEqual(cpu.reg_read(reg.UC_X86_REG_EFLAGS),0x202)
            if bits==64:
                for register,value in xmm.items():self.assertEqual(cpu.reg_read(register),value)
        else:
            self.assertEqual(started,[]);self.assertEqual(exited,[1])
