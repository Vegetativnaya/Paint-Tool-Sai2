import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import owner
import pe_guard
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

class LicensingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.blob=owner.public_blob(cls.key.public_key())
        cls.device=hashlib.sha256(b'01234567-89ab-cdef-0123-456789abcdef').hexdigest()

    def test_signed_license_and_recipient(self):
        data=owner.issue(self.key,self.device,'Получатель №1')
        info=owner.inspect_license(data,owner.load_public(self.blob))
        self.assertEqual(info['device'],self.device)
        self.assertEqual(info['recipient'],'Получатель №1')
        self.assertEqual(len(data),440)
        self.assertNotEqual(data,owner.issue(self.key,self.device,'Получатель №1'))

    def test_tampered_machine_name_and_signature_rejected(self):
        data=owner.issue(self.key,self.device,'Получатель')
        for position in (8,40,56,184,439):
            altered=bytearray(data);altered[position]^=1
            with self.subTest(position=position),self.assertRaises(InvalidSignature):
                owner.inspect_license(bytes(altered),self.key.public_key())

    def test_wrong_signer_and_bad_lengths(self):
        data=owner.issue(self.key,self.device,'Получатель')
        wrong=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        with self.assertRaises(InvalidSignature):owner.inspect_license(data,wrong.public_key())
        for value in (b'',data[:-1],data+b'\0'):
            with self.assertRaises(ValueError):owner.inspect_license(value,self.key.public_key())

    def test_bad_device_or_name(self):
        for code,name in [('x'*64,'Name'),('ab','Name'),(self.device,''),(self.device,'Я'*64),(self.device,'A\0B')]:
            with self.assertRaises(ValueError):owner.issue(self.key,code,name)

    def test_encrypted_owner_key_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory=Path(tmp)/'.owner'
            owner.create_owner(directory,'test-password-123')
            self.assertIn(b'ENCRYPTED PRIVATE KEY',(directory/'private-key.pem').read_bytes())
            with self.assertRaises(ValueError):owner.read_private(directory,'wrong-password')
            with self.assertRaises(ValueError):owner.create_owner(directory,'test-password-123')
            self.assertEqual(owner.public_blob(owner.read_private(directory,'test-password-123').public_key()),
                             (directory/'public.blob').read_bytes())

    def test_distribution_gate_and_tabletka_unchanged(self):
        before={p:hashlib.sha256(p.read_bytes()).hexdigest() for p in owner.PACKAGE.rglob('*') if p.is_file() and 'licensing' not in p.parts}
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'distribution'
            owner.build_distribution(output,self.blob)
            self.assertFalse((output/'licensing').exists())
            for bits in (32,64):
                folder=output/f'SAI2-RU-{bits}bit'
                protected=(folder/'sai2.exe').read_bytes()
                original=(owner.PACKAGE/folder.name/'sai2.exe').read_bytes()
                p,q=pe_guard.PE(original),pe_guard.PE(protected)
                self.assertNotEqual(p.u32(p.opt+16),q.u32(q.opt+16))
                self.assertIn(pe_guard.MARKER,protected)
                for section in p.sections:
                    start,size=section['raw'],section['size']
                    self.assertEqual(original[start:start+size],protected[start:start+size])
                gate=(folder/'SAI2RuLicense.dll').read_bytes()
                self.assertEqual(gate[gate.index(owner.SLOT)+16:gate.index(owner.SLOT)+292],self.blob)
                with self.assertRaises(ValueError):pe_guard.protect(protected)
            for p in (owner.PACKAGE/'Tabletka').rglob('*'):
                if p.is_file():self.assertEqual(p.read_bytes(),(output/'Tabletka'/p.relative_to(owner.PACKAGE/'Tabletka')).read_bytes())
            with self.assertRaises(ValueError):owner.build_distribution(output,self.blob)
        for p,digest in before.items():self.assertEqual(hashlib.sha256(p.read_bytes()).hexdigest(),digest)

    def test_modified_executable_rejected(self):
        original=(owner.PACKAGE/'SAI2-RU-64bit'/'sai2.exe').read_bytes()
        corrupted=bytearray(original);corrupted[2000]^=1
        with self.assertRaises(ValueError):pe_guard.protect(bytes(corrupted))

@unittest.skipUnless(os.environ.get('SAIRU_WINE') and os.environ.get('SAIRU_PROBE64') and os.environ.get('SAIRU_HOST64'),
                     'Set SAIRU_WINE, SAIRU_PROBE64 and SAIRU_HOST64 for native integration tests')
class NativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.blob=owner.public_blob(cls.key.public_key())

    def run_exe(self,path):
        result=subprocess.run([os.environ['SAIRU_WINE'],str(path)],capture_output=True,timeout=30,
                              cwd=path.parent)
        return result.returncode,result.stdout.decode('utf-8',errors='replace'),result.stderr.decode('utf-8',errors='replace')

    def test_native_signature_machine_binding_and_entrypoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);probe=root/'probe.exe';shutil.copy2(os.environ['SAIRU_PROBE64'],probe)
            gate=root/'SAI2RuLicense.dll'
            gate.write_bytes(owner.configure_gate((owner.HERE/'bin'/'gate64.dll').read_bytes(),self.blob))
            rc,out,err=self.run_exe(probe)
            self.assertEqual(rc,0,(out,err));self.assertIn('VALID=0',out)
            device=re.search(r'DEVICE=([0-9a-f]{64})',out).group(1)
            license=root/'translation.lic';valid=owner.issue(self.key,device,'Native test')
            cases=[('valid',valid,1),('wrong-machine',owner.issue(self.key,'f'*64,'Other PC'),0),
                   ('bad-length',valid[:-1],0)]
            altered=bytearray(valid);altered[60]^=1;cases.append(('tampered-name',bytes(altered),0))
            wrong=rsa.generate_private_key(public_exponent=65537,key_size=2048)
            cases.append(('wrong-signer',owner.issue(wrong,device,'Wrong signer'),0))
            for name,data,expected in cases:
                with self.subTest(name=name):
                    license.write_bytes(data);rc,out,err=self.run_exe(probe)
                    self.assertEqual(rc,0,(out,err));self.assertIn(f'VALID={expected}',out)
            # Test the actual native bootstrap on a console fixture with observable startup.
            original=Path(os.environ['SAIRU_HOST64']).read_bytes();digest=hashlib.sha256(original).hexdigest()
            pe_guard.APPROVED[digest]=64
            try:protected=pe_guard.protect(original)
            finally:del pe_guard.APPROVED[digest]
            host=root/'host.exe';host.write_bytes(protected)
            license.write_bytes(valid)
            rc,out,err=self.run_exe(host)
            self.assertEqual(rc,0,(out,err));self.assertIn('APP_STARTED',out)
            # The same ABI and verifier, without the modal error UI during negative tests.
            silent=bytearray(protected);offset=silent.index(b'CheckLicense\0')
            entry=pe_guard.PE(protected);self.assertLess(offset+14,entry.offset(entry.u32(entry.opt+16)))
            silent[offset:offset+14]=b'VerifyLicense\0';host.write_bytes(silent)
            for data in (None,owner.issue(self.key,'e'*64,'Other machine'),valid[:-1]):
                if data is None:license.unlink(missing_ok=True)
                else:license.write_bytes(data)
                rc,out,err=self.run_exe(host)
                self.assertEqual(rc,1,(out,err));self.assertNotIn('APP_STARTED',out)
            license.write_bytes(valid);gate.rename(root/'missing.dll')
            rc,out,err=self.run_exe(host)
            self.assertEqual(rc,1,(out,err));self.assertNotIn('APP_STARTED',out)
