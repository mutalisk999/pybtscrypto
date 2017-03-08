#!encoding=utf8

__author__ = 'mutalisk'

from setuptools import setup
from distutils.extension import Extension

ext_modules = [Extension("pybtscrypto", ["pybtscrypto/pybtscrypto.cpp", "pybtscrypto/city/city.cpp", "pybtscrypto/secp256k1/secp256k1.cpp"],
    language="c++",
    define_macros=[('_MSC_VER', None), ('_WIN32', None), ('MS_WIN64', None), ('USE_SCALAR_8X32', None), 
    	('USE_FIELD_10X26', None), ('USE_FIELD_INV_BUILTIN', None), ('USE_NUM_NONE', None), 
    	('USE_SCALAR_INV_BUILTIN', None), ('HAVE_ROUND', None)],
    include_dirs=["pybtscrypto/secp256k1", "pybtscrypto/city", "pywrapper-dependence/include"],
    library_dirs=["pywrapper-dependence/lib64-win"],
    libraries=["python27"]
    )]

setup(name='pybtscrypto',
    version='0.1.0',
    description='Python Wrapper of BTS crypto library',
    author='',
    author_email='',
    url='https://github.com/mutalisk999/pybtscrypto',
    platforms='win',
    packages=['pybtscrypto'],
    install_requires=["setuptools", "ecdsa"],
    zip_safe=False,
    ext_modules = ext_modules,
    )