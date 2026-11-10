# PyInstaller: run from the agent/ folder:  pyinstaller sentinel_agent.spec
a = Analysis(['run_agent.py'], pathex=['.'],
             hiddenimports=['win32timezone', 'win32crypt', 'servicemanager', 'win32serviceutil', 'win32service', 'win32event',
                            'watchdog.observers.winapi', 'sentinel.service', 'sentinel_service'],
             excludes=['cv2', 'numpy', 'tkinter'])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, a.binaries, a.datas, [], name='SentinelAgent', console=True, upx=False)
