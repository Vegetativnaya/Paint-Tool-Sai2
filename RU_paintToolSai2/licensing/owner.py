#!/usr/bin/env python3
"""Offline translation licensing. Private keys and issued licenses stay local."""
import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import sys
import uuid
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pe_guard import protect

HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
OWNER=HERE/'.owner'
MAGIC=b'SAIRUL01'
SLOT=b'SAIRU-PUBKEY-V1!'
PAYLOAD_SIZE=184
LICENSE_SIZE=440


def public_blob(key):
    numbers=key.public_numbers()
    if numbers.n.bit_length()!=2048 or numbers.e!=65537:
        raise ValueError('Требуется RSA-2048 с e=65537')
    return struct.pack('<BBHI4sII',6,2,0,0x2400,b'RSA1',2048,65537)+numbers.n.to_bytes(256,'little')


def load_public(blob):
    if len(blob)!=276 or blob[:20]!=struct.pack('<BBHI4sII',6,2,0,0x2400,b'RSA1',2048,65537):
        raise ValueError('Недопустимый открытый ключ')
    return rsa.RSAPublicNumbers(65537,int.from_bytes(blob[20:],'little')).public_key()


def create_owner(directory,password):
    if len(password)<12:raise ValueError('Пароль должен содержать не менее 12 символов')
    directory=Path(directory)
    if directory.exists():raise ValueError('Папка владельца уже существует. Не перезаписывайте действующий ключ.')
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    private=key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,
                              serialization.BestAvailableEncryption(password.encode('utf-8')))
    directory.mkdir(mode=0o700,parents=True)
    path=directory/'private-key.pem'
    with path.open('xb') as stream:stream.write(private)
    os.chmod(path,0o600)
    (directory/'public.blob').write_bytes(public_blob(key.public_key()))
    return key


def read_private(directory,password):
    return serialization.load_pem_private_key((Path(directory)/'private-key.pem').read_bytes(),password.encode('utf-8'))


def issue(key,device,recipient):
    if not re.fullmatch('[0-9a-fA-F]{64}',device):raise ValueError('Код устройства должен содержать 64 шестнадцатеричных символа')
    name=recipient.strip().encode('utf-8')
    if not name or len(name)>127 or b'\0' in name:raise ValueError('Имя получателя: от 1 до 127 байт UTF-8, без нулевых символов')
    payload=MAGIC+bytes.fromhex(device)+uuid.uuid4().bytes+name.ljust(128,b'\0')
    signature=key.sign(payload,padding.PKCS1v15(),hashes.SHA256())
    return payload+signature


def inspect_license(data,key):
    if len(data)!=LICENSE_SIZE or data[:8]!=MAGIC or data[183]!=0:raise ValueError('Неверный формат лицензии')
    key.verify(data[PAYLOAD_SIZE:],data[:PAYLOAD_SIZE],padding.PKCS1v15(),hashes.SHA256())
    return dict(device=data[8:40].hex(),license_id=str(uuid.UUID(bytes=data[40:56])),
                recipient=data[56:184].split(b'\0',1)[0].decode('utf-8'))


def configure_gate(template,blob):
    load_public(blob)
    if template.count(SLOT)!=1:raise ValueError('Неизвестный шаблон проверки лицензии')
    offset=template.index(SLOT)+len(SLOT)
    if template[offset:offset+276]!=bytes(276):raise ValueError('Шаблон уже настроен')
    return template[:offset]+blob+template[offset+276:]


def build_distribution(output,blob,package=PACKAGE):
    output=Path(output).resolve();package=Path(package).resolve()
    if output.exists():raise ValueError('Выходная папка уже существует. Выберите новую папку.')
    if output==package or package.is_relative_to(output) or any(output.is_relative_to(package/name) for name in ('SAI2-RU-32bit','SAI2-RU-64bit','Tabletka','licensing')):
        raise ValueError('Нельзя перезаписывать исходную папку или создавать результат внутри исходных компонентов')
    manifest=json.loads((HERE/'bin'/'manifest.json').read_text(encoding='utf-8'))
    # Validate everything before writing any distribution file.
    plans=[]
    for bits in (32,64):
        source=package/f'SAI2-RU-{bits}bit'
        binary=protect((source/'sai2.exe').read_bytes())
        template=(HERE/'bin'/f'gate{bits}.dll').read_bytes()
        if hashlib.sha256(template).hexdigest()!=manifest[f'gate{bits}.dll']:
            raise ValueError('Контрольная сумма шаблона DLL не совпадает')
        plans.append((source,binary,configure_gate(template,blob)))
    output.mkdir(parents=True)
    for source,binary,gate in plans:
        target=output/source.name
        shutil.copytree(source,target)
        (target/'sai2.exe').write_bytes(binary)
        (target/'SAI2RuLicense.dll').write_bytes(gate)
    # Preserve this folder byte-for-byte, without executing or modifying it.
    if (package/'Tabletka').is_dir():shutil.copytree(package/'Tabletka',output/'Tabletka')
    shutil.copy2(HERE/'CLIENT.md',output/'ПРОЧИТАЙТЕ.md')
    info={'product':'SAI2 Russian translation','public_key_sha256':hashlib.sha256(blob).hexdigest(),
          'license':'RSA-2048 / SHA-256, offline, Windows installation binding',
          'builds':{source.name:hashlib.sha256(binary).hexdigest() for source,binary,_ in plans}}
    (output/'distribution.json').write_text(json.dumps(info,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def menu(directory):
    while True:
        print('\nЛицензии русского перевода SAI 2')
        print('1 — Создать ключ владельца (один раз)')
        print('2 — Собрать защищённую папку для выдачи')
        print('3 — Выдать лицензию по коду устройства')
        print('4 — Проверить полученную лицензию')
        print('0 — Выход')
        choice=input('Выбор: ').strip()
        if choice=='0':return
        command=None
        if choice=='1':command=['init']
        elif choice=='2':command=['build']
        elif choice=='3':
            code=input('Код устройства: ').strip()
            name=input('Имя получателя: ').strip()
            command=['issue','--device',code,'--name',name]
        elif choice=='4':command=['inspect',input('Путь к translation.lic: ').strip().strip('"')]
        if command:
            try:main(['--owner-dir',str(directory)]+command)
            except (ValueError,OSError) as error:print('Ошибка:',error)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--owner-dir',type=Path,default=OWNER)
    sub=parser.add_subparsers(dest='command',required=True)
    sub.add_parser('menu',help='Интерактивное меню владельца')
    sub.add_parser('init',help='Создать закрытый ключ владельца (один раз)')
    build=sub.add_parser('build',help='Создать защищённую папку для выдачи')
    build.add_argument('--output',type=Path,default=PACKAGE/'licensed-distribution')
    grant=sub.add_parser('issue',help='Выдать лицензию на код устройства')
    grant.add_argument('--device',required=True)
    grant.add_argument('--name',required=True)
    grant.add_argument('--output',type=Path)
    view=sub.add_parser('inspect',help='Проверить подпись и прочитать лицензию')
    view.add_argument('license',type=Path)
    args=parser.parse_args(argv)
    if args.command=='menu':
        menu(args.owner_dir)
        return
    if args.command=='init':
        password=getpass.getpass('Придумайте пароль закрытого ключа (не менее 12 символов): ')
        if password!=getpass.getpass('Повторите пароль: '):raise ValueError('Пароли не совпадают')
        create_owner(args.owner_dir,password)
        print('Ключ создан. Сохраните резервную копию папки:',args.owner_dir)
        print('Не отправляйте её получателям и не загружайте в GitHub.')
    elif args.command=='build':
        build_distribution(args.output,(args.owner_dir/'public.blob').read_bytes())
        print('Защищённая сборка:',args.output.resolve())
        print('Выдавайте только эту папку; исходные EXE не защищены.')
    elif args.command=='issue':
        key=read_private(args.owner_dir,getpass.getpass('Пароль закрытого ключа: '))
        data=issue(key,args.device,args.name)
        metadata=inspect_license(data,key.public_key())
        target=args.output or HERE/'issued'/metadata['license_id']/'translation.lic'
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:stream.write(data)
        print('Лицензия создана:',target.resolve())
        print('Отправьте получателю только translation.lic')
    else:
        from cryptography.exceptions import InvalidSignature
        try:info=inspect_license(args.license.read_bytes(),load_public((args.owner_dir/'public.blob').read_bytes()))
        except InvalidSignature:raise ValueError('Подпись лицензии недействительна')
        print(json.dumps(info,ensure_ascii=False,indent=2))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as error:
        print('Ошибка:',error,file=sys.stderr);sys.exit(1)
