from distutils.core import setup, Extension
setup(name = 'malindexhelper', version = '1.0',  ext_modules = [Extension('malindexhelper', ['malindexhelper.c'], extra_compile_args = ["-Ofast"])])
