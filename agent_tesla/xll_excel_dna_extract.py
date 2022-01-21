#!/usr/bin/env python3
"""
Description: A script to extract .net assemblies from an XLL file that was built using Excel-DNA
Date: 2021-12-16
"""
__author__ = "Yaron Samuel"

import re
import lzma
import argparse
import os
from pefile import PE       
from typing import Dict, Optional

SCRIPT_DESCRIPTION = "A util to extract .net assemblies from an XLL file that was built using Excel-DNA"


def get_resource_buffer(pe: PE, entry) -> bytes:
    """
    helper function to get the resource buffer from a resource entry
    :param pe: PE object
    :param entry: resource entry
    :return: bytearray with the contents of the resource
    """
    rsrc_offset: int = entry.directory.entries[0].data.struct.OffsetToData
    size = entry.directory.entries[0].data.struct.Size
    return pe.get_memory_mapped_image()[rsrc_offset: rsrc_offset + size]


def extract_assemblies_from_excel_dna(xll_path: str, only_external: bool=True) -> Dict[str, bytes]:
    """
    Extracts assemblies from a given xll built with Excel-DNA
    :param xll_path:  path to Excel-DNA XLL file
    :param only_external: bool indicates if only external assemblies will be extracted,
                          otherwise the framework's assemblies will be extracted as well
    :return: a dictionary that maps an assembly name to its contents
    """
    pe = PE(xll_path)
    assemblies = {}
    external_libraries = []
    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        # extract assemblies
        if rsrc.name and rsrc.name.decode() in ['ASSEMBLY', 'ASSEMBLY_LZMA']:
            for entry in rsrc.directory.entries:
                if entry.name:
                    raw_buff = get_resource_buffer(pe, entry)
                    if rsrc.name.decode() == 'ASSEMBLY_LZMA':
                        assemblies[entry.name.decode()] = lzma.decompress(raw_buff)
                    else:
                        assemblies[entry.name.decode()] = raw_buff

        # parse the main xml
        elif rsrc.name and rsrc.name.decode() == 'DNA':
            for entry in rsrc.directory.entries:
                if entry.name and entry.name.decode() == '__MAIN__':
                    main_xml = get_resource_buffer(pe, entry).decode()
                    libs = re.findall('ExternalLibrary.{,200} Path="(.*?)"', main_xml)
                    external_libraries.extend([name.replace('packed:','') for name in libs])

    if only_external:
        # filter out non-external assemblies
        assemblies = {name: buff for name, buff in assemblies.items() if name in external_libraries}

    return assemblies


def save_files(assembly_dict: Dict[str, bytes], output_dir: str):
    """
    Saves the assemblies on assembly_dict to output_dir
    :param assembly_dict: a dictionary that maps an assembly name to its contents
    :param output_dir: output directory
    :return: None
    """
    os.makedirs(output_dir, exist_ok=True)
    for asm_name, contents in assembly_dict.items():
        asm_name = os.path.basename(asm_name)
        full_out_path = os.path.join(output_dir, asm_name)
        with open(full_out_path, 'wb') as fh:
            fh.write(contents)


def main():
    opt = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description=SCRIPT_DESCRIPTION)
    opt.add_argument('-o', '--output', default=".", help='output directory')
    opt.add_argument('-a', '--all', default=False, action="store_true",
                     help='Extract Excel-DNA framework assemblies')
    opt.add_argument('input', action='store', help='input XLL Excel-DNA file')
    args = opt.parse_args()

    assembly_dict = extract_assemblies_from_excel_dna(args.input, not args.all)
    if not args.output:
        output_dir = os.path.abspath(os.path.expanduser(os.path.expandvars('.')))
    else:
        output_dir = os.path.abspath(os.path.expanduser(os.path.expandvars(args.output)))

    save_files(assembly_dict, output_dir)


if __name__ == '__main__':
    main()
