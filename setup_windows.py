#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 파일 연결 등록 스크립트
────────────────────────────────
.locked 파일을 더블클릭하면 folderLock.py가 열리도록
레지스트리(HKEY_CURRENT_USER)에 파일 연결을 등록합니다.

사용법:
    python setup_windows.py            # 등록
    python setup_windows.py --remove   # 등록 해제
"""

import sys
import subprocess
from pathlib import Path

if sys.platform != "win32":
    print("이 스크립트는 Windows에서만 실행할 수 있습니다.")
    sys.exit(1)

import winreg

SCRIPT = Path(__file__).resolve().parent / "folderLock.py"
FILE_TYPE_ID = "FolderLock.locked"
HKCU = winreg.HKEY_CURRENT_USER


def _find_pythonw() -> str:
    """콘솔 창 없이 실행되는 pythonw.exe 경로 반환."""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return str(pythonw) if pythonw.exists() else sys.executable


def _set_key(path: str, value: str):
    with winreg.CreateKey(HKCU, path) as key:
        winreg.SetValueEx(key, "", 0, winreg.REG_SZ, value)


def _delete_key_tree(path: str):
    """키와 하위 키를 모두 삭제 (없으면 무시)."""
    try:
        winreg.DeleteKey(HKCU, path)
    except FileNotFoundError:
        pass


def register():
    pythonw = _find_pythonw()
    command = f'"{pythonw}" "{SCRIPT}" "%1"'

    # .locked 확장자 → 파일 형식 ID 연결
    _set_key(r"Software\Classes\.locked", FILE_TYPE_ID)

    # 파일 형식 설명
    _set_key(rf"Software\Classes\{FILE_TYPE_ID}", "잠긴 폴더 (Folder Lock)")

    # 더블클릭 시 실행 명령
    _set_key(rf"Software\Classes\{FILE_TYPE_ID}\shell\open\command", command)

    # Windows 탐색기에 변경 사항 알림
    try:
        subprocess.run(
            ["ie4uinit.exe", "-show"],
            capture_output=True, timeout=5,
        )
    except Exception:
        pass

    print("=" * 50)
    print("  등록 완료!")
    print(f"  Python : {pythonw}")
    print(f"  Script : {SCRIPT}")
    print()
    print("  .locked 파일을 더블클릭하면 Folder Lock이 열립니다.")
    print("=" * 50)


def remove():
    for key_path in [
        rf"Software\Classes\{FILE_TYPE_ID}\shell\open\command",
        rf"Software\Classes\{FILE_TYPE_ID}\shell\open",
        rf"Software\Classes\{FILE_TYPE_ID}\shell",
        rf"Software\Classes\{FILE_TYPE_ID}",
        r"Software\Classes\.locked",
    ]:
        _delete_key_tree(key_path)

    print("=" * 50)
    print("  등록 해제 완료!")
    print("  .locked 파일 연결이 제거되었습니다.")
    print("=" * 50)


if __name__ == "__main__":
    if "--remove" in sys.argv:
        remove()
    else:
        register()
