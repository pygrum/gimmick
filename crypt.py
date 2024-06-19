#!/usr/bin/env python3

import pefile
import argparse
from Crypto.Cipher import ARC4

RC4_KEY = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'

if __name__ in '__main__':
    try:
        parser = argparse.ArgumentParser(description='Encrypts PE Sections.')
        parser.add_argument('-f', required=True, help='Path to the source executable', type=str)
        parser.add_argument('-o', required=True, help='Path to store the output executable', type=str)
        parser.add_argument('-s', nargs='+', required=True, help='Sections to encrypt')
        option = parser.parse_args()

        exe = pefile.PE(option.f)
        for section in exe.sections:
            name = section.Name.rstrip(b'\x00').decode('utf-8')
            for s in option.s:
                if name == s:
                    print("[*] encrypting", name+"...", end=" ")
                    section_data = section.get_data()

                    # need to recreate cipher due to RC4 limitations
                    cipher = ARC4.new(RC4_KEY)
                    new_section_data = cipher.encrypt(section_data)

                    exe.set_data_bytes(section.PointerToRawData, new_section_data)

                    print("done!")
        exe.write(option.o)

    except Exception as e:
        print('[!] error: {}'.format(e))
