import sys
import argparse
import string
from typing import Tuple


def get_printable_string(data: bytearray) -> str:
    count = 0
    for n in range(0, len(data)):
        if not (0x20 <= data[n] < 0x80):
            break
        count += 1

    return str(data[0:count].decode('utf-8'))


def get_printable_utf16_string(data: bytearray) -> str:
    count = 0
    for n in range(0, len(data) - 1):
        c = data[n]
        d = data[n + 1]
        
        if c == 0 and d == 0:
            break
        
        if c == 0:
            count += 1
            continue
        
        if not (0x20 <= c < 0x80):
            break
        count += 1

    return str(data[0:count].decode('utf-16'))


def decrypt_string(key: bytes, data: bytes) -> Tuple[str, bool]:
    result = decrypt_xor(key, data)
    utf16 = False
    try:
        tmp = get_printable_string(result)
        if len(tmp) <= 1:
            tmp = get_printable_utf16_string(result)
            utf16 = True
        result = tmp
    except UnicodeDecodeError:
        result = ''

    return result, utf16
    
    
def decrypt_xor(key: bytes, data: bytes) -> bytearray:
    result = bytearray()
    for n in range(0, len(data)):
        c = data[n] ^ key[n % len(key)]
        result.append(c)
    return result


def find_key(buffer: bytes, min_key_scan_length: int):
    # this is the pattern that we are trying to brute force
    pattern = b'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko'
    key = None
    
    for n in range(0, len(buffer)):
        if buffer[n:n + 1] == 0:
            continue
        
        data = buffer[n:n + min_key_scan_length]
        result = decrypt_xor(pattern[0:min_key_scan_length], data)
        if len(result) == min_key_scan_length and result in buffer:
            key = decrypt_xor(pattern, buffer[n:n + len(pattern)])
            
            # check if key is shorter
            key_start = key[0:2]
            key_pos = key[4:].find(key_start)
            if key_pos != -1:
                key = key[0:4 + key_pos]
            
            # verify if the full key is in the file
            if key not in buffer:
                key = None
                continue
            
            # key is in file
            break

    return key


def scan(buffer: bytes, min_length: int, max_length: int):
    key = find_key(buffer, 8)
    if key is None:
        print('No key found.')
        return
    
    print(f'Using key for decryption: {key.hex()}')

    payload_urls = []
    offset = 0
    while offset + max_length <= len(buffer):
        data = buffer[offset:offset + max_length]
        if data[0] == 0x00:
            offset += 1
            continue
        
        decrypted, is_utf16 = decrypt_string(key, data)
        if len(decrypted) >= min_length:
            print(f'{offset:#x}: {decrypted}')

        if ('http' in decrypted or (decrypted.count('.') >= 2 and '/' in decrypted)) and 'Gecko' not in decrypted:
            payload_urls.append(decrypted)
        
        if is_utf16:
            offset += max(1, len(decrypted) * 2)
        else:
            offset += max(1, len(decrypted))

    if payload_urls:
        print('')
    
    for url in payload_urls:
        if not url.startswith('http'):
            # https URLs have an "s" as their 4. character
            if url[4] == 's':
                print(f'Payload URL: https://{url[8:]}')
            else:
                print(f'Payload URL: http://{url[7:]}')
        else:
            print(f'Payload URL: {url}')


def main():
    parser = argparse.ArgumentParser(description='GuLoader strings decoder by brute forcing the key')
    parser.add_argument('filename', default='', type=str, help='Filename')
    parser.add_argument('--min-length', default=6, type=int, help='Minimum string length')
    parser.add_argument('--max-length', default=128, type=int, help='Maximum string length')
    args = parser.parse_args()
    
    with open(args.filename, 'rb') as f:
        scan(f.read(), args.min_length, args.max_length)


if __name__ == '__main__':
    main()

