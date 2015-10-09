# -*- mode: python -*-

block_cipher = None

def Datafiles(*filenames, **kw):
    import os

    def datafile(path, strip_path=True):
        parts = path.split('/')
        path = name = os.path.join(*parts)
        if strip_path:
            name = os.path.basename(path)
        return name, path, 'DATA'

    strip_path = kw.get('strip_path', True)
    return TOC(
        datafile(filename, strip_path=strip_path)
        for filename in filenames
        if os.path.isfile(filename))

common_data = Datafiles('leap/common/ca_cert.pem', strip_path=False)


a = Analysis(['bitmask.py'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None,
             excludes=None,
             win_no_prefer_redirects=None,
             win_private_assemblies=None,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='bitmask',
          debug=True,
          strip=None,
          upx=True,
          console=False)
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               common_data,
               strip=None,
               upx=True,
               name='bitmask')
import sys
if sys.platform.startswith("darwin"):
	app = BUNDLE(coll,
		     name=os.path.join(
		      'dist', 'Bitmask.app'),
                     appname='Bitmask',
                     version='0.9.0rc4',
		     icon='pkg/osx/bitmask.icns',
		     bundle_identifier='bitmask-0.9.0rc4')
