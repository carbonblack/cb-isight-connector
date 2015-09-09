# -*- mode: python -*-
a = Analysis(['scripts/isight'],
             pathex=['.'],
             hiddenimports=['unicodedata'],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='isight',
          debug=False,
          strip=False,
          upx=True,
          console=True )