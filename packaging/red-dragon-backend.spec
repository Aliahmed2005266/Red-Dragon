# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller specification for the Red Dragon scanning engine.

Builds a self-contained backend so the installer does not depend on a system
Python: every library the scanners need is collected into the bundle.

A one-folder build is used rather than one-file on purpose. A one-file build
extracts its whole payload to a temp directory on every launch, which adds
several seconds to start-up; one-folder starts immediately. The Electron
installer ships the whole folder as a single extraResource, so the user still
installs one thing.

Run with:  pyinstaller packaging/red-dragon-backend.spec
"""

import os
import sys

# The spec is executed with the project root as the working directory.
ROOT = os.path.abspath(os.path.join(SPECPATH, ".."))
BACKEND = os.path.join(ROOT, "backend")

# Bundle the compiled React app next to the executable. The backend looks for
# a "ui" folder beside itself, so the layout inside the bundle is:
#   red-dragon-backend/          (executable + libraries)
#   ui/                         (index.html + assets)
ui_build = os.path.join(ROOT, "frontend", "build")
if not os.path.isfile(os.path.join(ui_build, "index.html")):
    sys.exit(
        "The interface has not been built yet.\n"
        "Run:  npm run build:ui\n"
        "before packaging the backend."
    )

# ai_agent and its siblings are imported lazily inside request handlers, so
# PyInstaller cannot see them by static analysis. Listing them here stops them
# being stripped out of the bundle.
hiddenimports = [
    "ai_agent",
    "server_extensions",
    "scanner_modules.ai_agent",
    "scanner_modules.ai_security_agent",
    "scanner_modules.ai_scanner",
    "scanner_modules.encoding_handler",
    "scanner_modules.finding_dedupe",
    "scanner_modules.param_discovery",
    "scanner_modules.poc_evidence",
    "scanner_modules.tech_fingerprint",
    "scanner_modules.web_proxy",
    "config_store",
    # Provider SDKs are optional at runtime but must ship if imported at all
    "openai",
    "anthropic",
    "google.generativeai",
    "mistralai",
    "cohere",
    "dns",
    "bs4",
    "flask_cors",
    "requests",
]

datas = [(ui_build, "ui")]

# Some SDKs ship C extensions and data files that a plain dependency walk
# misses, so ask PyInstaller to collect them wholesale. Each is optional: a
# provider the user has not installed should not fail the build.
collect_all = [
    "openai", "anthropic", "requests", "flask", "flask_cors",
    "dns", "bs4", "werkzeug", "jinja2", "itsdangerous", "click",
]

datas_hook, binaries, hidden_hook = [], [], []
for _name in collect_all:
    try:
        from PyInstaller.utils.hooks import collect_all as _collect
        _d, _b, _h = _collect(_name)
        datas_hook += _d
        binaries += _b
        hidden_hook += _h
    except Exception:
        # Missing optional dependency: carry on without it.
        pass

datas += datas_hook
hiddenimports += hidden_hook

a = Analysis(
    [os.path.join(BACKEND, "desktop.py")],
    pathex=[BACKEND],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Nothing here talks to a Qt or Tk toolkit, so drop the heavy GUI stacks
    # that would otherwise be pulled in by a dependency.
    excludes=[
        "tkinter", "matplotlib", "numpy", "pandas", "PyQt5", "PyQt6",
        "PySide2", "PySide6", "wx", "IPython", "pytest", "setuptools",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="red-dragon-backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-packed Python bundles are a common malware trigger
    console=False,  # a GUI app should not flash a console window on Windows
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="red-dragon-backend",
)
