"""
Persistent Settings for the Installed Application

The desktop app needs somewhere to keep a small amount of state between runs:
whether the user has accepted the authorisation notice, their last targets, UI
preferences, and which AI provider they configured.

API keys are deliberately NOT stored here. They are held in memory for the
lifetime of an AI session and are never written to disk, so a stolen settings
file cannot leak a provider credential. When the user asks the desktop shell to
remember a key, the shell encrypts it with the operating system keychain and
hands the ciphertext to the shell to store, never the backend.

The file lives in the per-user application data directory, not next to the
executable, so it works when the app is installed in a protected location and
survives a reinstall.
"""

import os
import sys
import json
import threading

# Bumped when the shape of the stored data changes in a way that matters.
SCHEMA_VERSION = 1

# Defaults are deliberately conservative: authorisation starts unaccepted so
# the first launch shows the notice rather than silently skipping it.
DEFAULTS = {
    'schema': SCHEMA_VERSION,
    'authorized': False,
    'authorized_at': None,
    'authorized_target': '',
    'default_target': '',
    'targets': [],
    'ai_provider': '',
    'ai_model': '',
    'theme': 'dark',
    'auto_update': True,
    'last_scan_target': '',
}

_write_lock = threading.Lock()


def get_store_path():
    """Resolve the settings file location for the current platform."""
    override = os.environ.get('RED_DRAGON_CONFIG_DIR')
    if override:
        base = override
    elif sys.platform == 'win32':
        base = os.environ.get('APPDATA') or os.path.expanduser('~')
        base = os.path.join(base, 'RedDragon')
    elif sys.platform == 'darwin':
        base = os.path.join(os.path.expanduser('~'), 'Library',
                            'Application Support', 'RedDragon')
    else:
        base = os.environ.get('XDG_CONFIG_HOME') or os.path.join(
            os.path.expanduser('~'), '.config')
        base = os.path.join(base, 'red-dragon')

    return os.path.join(base, 'settings.json')


def get_store():
    """Read the settings file, returning defaults for anything missing.

    A corrupt or unreadable file must never stop the app from starting, so any
    problem reading it falls back to defaults rather than raising.
    """
    path = get_store_path()
    data = dict(DEFAULTS)
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            stored = json.load(fh)
        if isinstance(stored, dict):
            for key, value in stored.items():
                if key in DEFAULTS:
                    data[key] = value
    except (OSError, ValueError):
        pass
    except Exception:
        pass
    return data


def save_store(data):
    """Write settings back, creating the directory if needed.

    Returns (ok, path). Failures are reported rather than raised so a
    read-only profile cannot crash the app mid-scan.
    """
    path = get_store_path()
    clean = dict(DEFAULTS)
    if isinstance(data, dict):
        for key, value in data.items():
            if key in DEFAULTS:
                clean[key] = value
    clean['schema'] = SCHEMA_VERSION

    with _write_lock:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # Write to a temp file then replace, so a crash mid-write cannot
            # leave a truncated settings file behind.
            tmp = path + '.tmp'
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump(clean, fh, indent=2)
            os.replace(tmp, path)
            # Settings can hold target hosts, so keep them user-only.
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            return True, path
        except OSError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, str(exc)


def remember_target(target, limit=25):
    """Add a target to the recents list, newest first, without duplicates."""
    target = (target or '').strip()
    if not target:
        return get_store()
    data = get_store()
    recents = [t for t in (data.get('targets') or []) if t != target]
    recents.insert(0, target)
    data['targets'] = recents[:limit]
    data['last_scan_target'] = target
    if not data.get('default_target'):
        data['default_target'] = target
    save_store(data)
    return data
