#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows 탐색기 통합 등록 스크립트
────────────────────────────────
HKEY_CURRENT_USER 레지스트리에 두 가지를 등록한다:
  ▸ 폴더 우클릭 → "🔒 폴더 잠금"   → folderLock.py 호출
  ▸ .locked 더블클릭             → folderLock.py 호출 (자동 해제)

사용법:
    python setup_windows.py            # 등록
    python setup_windows.py --remove   # 등록 해제
"""

import sys

if sys.platform != "win32":
    print("이 스크립트는 Windows에서만 실행할 수 있습니다.")
    sys.exit(1)

from folderLock import WindowsIntegration


def register():
    integ = WindowsIntegration()
    integ.register()
    print("=" * 50)
    print("  등록 완료!")
    print(f"  Python : {integ.python_exe}")
    print(f"  Script : {integ.script_path}")
    print()
    print("  ▸ 폴더 우클릭 → \"🔒 폴더 잠금\"")
    print("  ▸ .locked 파일 더블클릭 → 자동 해제")
    print("=" * 50)


def remove():
    WindowsIntegration().unregister()
    print("=" * 50)
    print("  등록 해제 완료!")
    print("  탐색기 우클릭 메뉴 및 .locked 파일 연결이 제거되었습니다.")
    print("=" * 50)


if __name__ == "__main__":
    if "--remove" in sys.argv:
        remove()
    else:
        register()
