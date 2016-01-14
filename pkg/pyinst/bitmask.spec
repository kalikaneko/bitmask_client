# -*- mode: python -*-

block_cipher = None

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
