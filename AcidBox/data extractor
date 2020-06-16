"""
Data extraction script for AcidBox malware samples.
This malware family keeps data encoded + compressed
appended to icons in the resource section.
Written by Dominik Reichel and Esmid Idrizovic
"""

import os
import sys
import zlib
import pefile
import argparse
import binascii


class AcidBoxExtractor(object):
    DATA_MARKER: bytes = b'\x56\x89\x69\xB6'
    KEY: bytes = b'\xCC\xEC\x0C\x2C\x4C\x6C\x8C\xAC'
    ICON_ID: bytes = b'\xEC\xCF\x9D\xF5\xF1\xD3\x9E\xF5\xF2\xD4\x9F\xF5\xBD\xAB\x90\xF5'

    def decode(self, data: bytearray, name: int) -> bytes:
        for i in range(len(data)):
            data[i] ^= self.KEY[i % 8]

        marker: str = data[0:4].hex()
        uncompressed_crc32: str = hex(int.from_bytes(data[4:8], byteorder='little'))
        uncompressed_size: int = int.from_bytes(data[8:12], byteorder='little')
        option: int = int.from_bytes(data[12:16], byteorder='little')
        uncompressed_data: bytes = b''
        try:
            uncompressed_data = zlib.decompress(data[16:], 15+32)
            if uncompressed_crc32 != hex(binascii.crc32(uncompressed_data)):
                print('[-] Warning: CRC32 is not correct')
            print(f'[+] Resource: {name}')
            print(f'[+] Marker bytes: 0x{marker}')
            if option == 1:
                opt = '0x1 (Data encrypted)'
            elif option == 2:
                opt = '0x2 (Data zlib compressed)'
            else:
                opt = 'Unknown'
            print(f'[+] Option: {opt}')
            print(f'[+] Decrypted/Uncompressed data CRC32: {uncompressed_crc32}')
            print(f'[+] Decrypted/Uncompressed data size: {uncompressed_size} bytes')
        except zlib.error:
            print('[-] Error: zlib decompression failed')

        return uncompressed_data

    def run(self, filename: str) -> None:
        print('AcidBox data extractor v1.0')
        print('*~*~*~*~*~*~*~*~*~*~*~*~*~*')
        if not os.path.isfile(filename):
            print('[-] Error: Input file does not exist or is invalid')
            return
        try:
            pe = pefile.PE(filename)
            for resource_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_entry.id != 3:  # 3 = RT_ICON
                    continue
                for entry in resource_entry.directory.entries:
                    icon_offset: int = entry.directory.entries[0].data.struct.OffsetToData
                    icon_size: int = entry.directory.entries[0].data.struct.Size
                    icon_data: bytearray = bytearray(pe.get_memory_mapped_image()[icon_offset:icon_offset + icon_size])
                    if icon_data.find(self.ICON_ID) == -1:
                        continue
                    data_offset = icon_data.find(self.DATA_MARKER)
                    if data_offset == -1:
                        continue
                    decoded_data: bytes = self.decode(icon_data[data_offset:], entry.id)
                    if decoded_data is None:
                        continue
                    file_basename: str = os.path.splitext(os.path.basename(filename))[0]
                    output_dir: str = os.path.join(os.path.dirname(filename), f"{file_basename}_extracted")
                    try:
                        if not os.path.exists(output_dir):
                            os.mkdir(output_dir)
                    except OSError:
                        print("[-] Error: Output directory creation failed")
                        return
                    with open(os.path.join(output_dir, str(entry.id)), 'wb') as f:
                        f.write(decoded_data)
                    print(f"[+] Extracted data written to: {os.path.join(output_dir, str(entry.id))}")
                    print("-~-~-")
        except pefile.PEFormatError:
            print('[-] Error: Input file is not a PE file')
        print('[+] Data extraction finished')


def main():
    parser = argparse.ArgumentParser(prog='acidbox_data_extractor.py', description='AcidBox malware data extractor')
    parser.add_argument(dest='input_file', type=str, help='AcidBox malware sample')
    args = parser.parse_args()

    ab = AcidBoxExtractor()
    ab.run(args.input_file)


if __name__ == '__main__':
    main()
