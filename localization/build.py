#!/usr/bin/env python3
"""Build Russian SAI 2024.11.23 copies. Python 3.9+, standard library only."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct

ROOT = Path(__file__).resolve().parents[1]
HASHES = {
    '32bit': '6fbccbdd23de9fca046d3d879f67c5ed7ed16df18714dfad201ba85662c93053',
    '64bit': 'f034c8be9ec62d768d0b363cd53df696a63958b9ea8f9191eaf9d08f084fd8f3',
}
ASSETS = {
    'Blots': 'Пятна', 'Blots&Noise': 'Пятна и шум',
    'Bristle': 'Щетина', 'Flat Bristle': 'Плоская щетина',
    'Flat Face': 'Плоский срез', 'Water Blur': 'Водяное размытие',
    'Canvas': 'Холст', 'Paper': 'Бумага', 'Water Color 1': 'Акварель 1',
    'Water Color 2': 'Акварель 2', 'Stars': 'Звёзды',
}

def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment

class PE:
    def __init__(self, data):
        self.data = data
        self.pe = struct.unpack_from('<I', data, 0x3c)[0]
        if data[:2] != b'MZ' or data[self.pe:self.pe+4] != b'PE\0\0':
            raise ValueError('Not a PE file')
        self.opt = self.pe + 24
        self.bits = 64 if self.u16(self.opt) == 0x20b else 32
        self.width = self.bits // 8
        self.fmt = '<Q' if self.bits == 64 else '<I'
        self.base = struct.unpack_from(self.fmt, data, self.opt + (24 if self.bits == 64 else 28))[0]
        self.filealign = self.u32(self.opt + 36)
        self.sectalign = self.u32(self.opt + 32)
        self.sections = []
        start = self.opt + self.u16(self.pe + 20)
        for i in range(self.u16(self.pe + 6)):
            header = start + i * 40
            name, virtual_size, rva, size, raw = struct.unpack_from('<8sIIII', data, header)
            self.sections.append(dict(header=header, name=name, vs=virtual_size, rva=rva, size=size, raw=raw))
        self.directory = self.opt + (112 if self.bits == 64 else 96)

    def u16(self, offset):
        return struct.unpack_from('<H', self.data, offset)[0]

    def u32(self, offset):
        return struct.unpack_from('<I', self.data, offset)[0]

    def offset(self, va):
        rva = va - self.base
        for s in self.sections:
            if s['rva'] <= rva < s['rva'] + s['size']:
                return s['raw'] + rva - s['rva']
        raise ValueError('Unmapped address')

    def string(self, va):
        offset = self.offset(va)
        end = offset
        while end + 2 <= len(self.data) and end-offset <= 32768 and self.data[end:end+2] != b'\0\0':
            end += 2
        if end - offset > 32768 or end + 2 > len(self.data):
            raise ValueError('Invalid string')
        return self.data[offset:end].decode('utf-16le')

    def relocations(self):
        rva, size = struct.unpack_from('<II', self.data, self.directory + 5 * 8)
        if not rva:
            return None
        pos = self.offset(self.base + rva)
        end = pos + size
        result = set()
        while pos < end:
            page, block = struct.unpack_from('<II', self.data, pos)
            if block < 8 or pos + block > end:
                raise ValueError('Invalid relocation block')
            for q in range(pos+8, pos+block, 2):
                entry = self.u16(q)
                if entry >> 12 == (10 if self.bits == 64 else 3):
                    result.add(page + (entry & 4095))
            pos += block
        return result

def checksum(data, offset):
    struct.pack_into('<I', data, offset, 0)
    total = 0
    for i in range(0, len(data), 2):
        total += int.from_bytes(data[i:i+2], 'little')
        total = (total & 65535) + (total >> 16)
    total = (total & 65535) + (total >> 16)
    struct.pack_into('<I', data, offset, total + len(data))

def patch(source, catalog):
    original = source.read_bytes()
    pe = PE(original)
    lookup = {(r['key'], r['en']): r['ru'] for r in catalog}
    changes = []
    matched = set()
    # Translation tables store adjacent key/value pointers. Do not replace raw
    # string occurrences, code, file extensions, registry keys or format tokens.
    for section in pe.sections:
        if section['name'].rstrip(b'\0') not in (b'.rdata', b'.data'):
            continue
        for offset in range(section['raw'], section['raw']+section['size']-2*pe.width, pe.width):
            keyva, textva = struct.unpack_from('<QQ' if pe.bits == 64 else '<II', original, offset)
            try:
                key = pe.string(keyva)
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{2,100}', key):
                    continue
                text = pe.string(textva)
            except (ValueError, UnicodeError):
                continue
            pair = (key, text)
            if pair in lookup:
                matched.add(pair)
                if lookup[pair] != text:
                    changes.append((offset+pe.width, lookup[pair], key))
    expected = {k for k, ru in lookup.items() if ru != k[1] and not (pe.bits == 64 and (k[0].endswith('32') or '(32bit)' in k[1])) and not (pe.bits == 32 and (k[0].endswith('64') or '(64bit)' in k[1]))}
    missing = expected - matched
    if missing:
        raise ValueError(f'{source}: missing translation records: {sorted(missing)}')
    last = max(pe.sections, key=lambda s: s['raw'] + s['size'])
    if last != max(pe.sections, key=lambda s: s['rva']):
        raise ValueError('Incompatible PE section order')
    if len(original) != last['raw'] + last['size']:
        raise ValueError('Unexpected overlay; refusing to discard it')
    security = struct.unpack_from('<II', original, pe.directory + 4 * 8)
    if security != (0, 0):
        raise ValueError('Signed executable requires a separate localization method')
    relocs = pe.relocations()
    if relocs is None and pe.u16(pe.opt+70) & 0x40:
        raise ValueError('ASLR without relocation information')
    data = bytearray(original)
    address = {}
    for offset, ru, key in changes:
        if ru not in address:
            address[ru] = pe.base + last['rva'] + len(data) - last['raw']
            data.extend(ru.encode('utf-16le') + b'\0\0')
        if relocs is not None:
            section = next(s for s in pe.sections if s['raw'] <= offset < s['raw']+s['size'])
            rva = section['rva'] + offset-section['raw']
            if rva not in relocs:
                raise ValueError(f'Pointer without ASLR relocation: {key}')
        struct.pack_into(pe.fmt, data, offset, address[ru])
    virtual_size = len(data) - last['raw']
    data.extend(b'\0' * (align(len(data), pe.filealign) - len(data)))
    raw_size = len(data) - last['raw']
    struct.pack_into('<I', data, last['header']+8, virtual_size)
    struct.pack_into('<I', data, last['header']+16, raw_size)
    flags = pe.u32(last['header']+36)
    struct.pack_into('<I', data, last['header']+36, (flags | 0x40000040) & ~0x02000000)
    struct.pack_into('<I', data, pe.opt+56, align(last['rva']+virtual_size, pe.sectalign))
    struct.pack_into('<I', data, pe.opt+8, pe.u32(pe.opt+8)+raw_size-last['size'])
    checksum(data, pe.opt+64)
    result = PE(data)
    for offset, ru, key in changes:
        pointer = struct.unpack_from(pe.fmt, data, offset)[0]
        if result.string(pointer) != ru:
            raise ValueError(f'Invalid translated pointer: {key}')
    # Instructions, imports, skin layouts and embedded assets must remain identical.
    for section in pe.sections:
        if section['name'].rstrip(b'\0') in (b'.text', b'.code', b'.appskin', b'.srclibs'):
            start, length = section['raw'], section['size']
            if data[start:start+length] != original[start:start+length]:
                raise ValueError('Unexpected executable code/asset modification')
    return bytes(data), dict(bits=pe.bits, translated_pointers=len(changes),
                             translated_strings=len(address), input_sha256=hashlib.sha256(original).hexdigest(),
                             output_sha256=hashlib.sha256(data).hexdigest(),
                             validation='Static PE/pointer/code-integrity checks passed; Windows launch not tested')

def localize_ini(source, target):
    raw = source.read_bytes()
    text = raw.decode('utf-16' if raw.startswith(b'\xff\xfe') else 'utf-8')
    lines = [line for line in text.splitlines() if not line.lstrip().startswith(';')]
    header = '; Настройки SAI 2. Имена разделов и параметров являются служебными.\n'
    if source.name == 'sai2.ini':
        header += '; lang = en выбирает встроенную таблицу, переведённую на русский.\n'
        header += '; Для параметров планшета: yes — включить, no — выключить.\n'
    else:
        header += '; Начальные параметры формы кисти. Числовые значения сохранены.\n'
        header += '; AngleControl: 0 — нет; 1 — автоматически; 2 — направление пера.\n'
        header += '; Angle — угол в градусах; Jitter — случайный разброс; Scaling — масштаб.\n'
    target.write_bytes((header+'\n'.join(lines)+'\n').replace('\n','\r\n').encode('utf-16'))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'Русская версия')
    args = parser.parse_args()
    catalog = json.loads((Path(__file__).parent/'ru.json').read_text(encoding='utf-8'))
    reports = []
    for bits, digest in HASHES.items():
        source = ROOT / 'Easy Paint Tool SAI 2' / f'Paint Tool SAI 2 ({bits})'
        exe = source/'sai2.exe'
        if hashlib.sha256(exe.read_bytes()).hexdigest() != digest:
            raise ValueError(f'Unsupported source build: {exe}')
        target = args.output / f'SAI2-RU-{bits}'
        target.mkdir(parents=True, exist_ok=True)
        binary, report = patch(exe, catalog)
        (target/'sai2.exe').write_bytes(binary)
        # English selects the localized English table. "ru" is not supported by SAI.
        localize_ini(source/'sai2.ini', target/'sai2.ini')
        shutil.copytree(source/'init', target/'init', dirs_exist_ok=True)
        for path in list((target/'init').rglob('*')):
            if path.is_file() and path.stem in ASSETS:
                renamed = path.with_stem(ASSETS[path.stem])
                path.replace(renamed)
                if renamed.suffix == '.ini':
                    localize_ini(renamed, renamed)
        reports.append(report)
    shutil.copy2(Path(__file__).parent/'README.md', args.output/'ПРОЧИТАЙТЕ.md')
    (args.output/'validation.json').write_text(json.dumps(reports, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(reports, ensure_ascii=False, indent=2))

if __name__ == '__main__':
    main()
