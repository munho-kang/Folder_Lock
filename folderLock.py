#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║        🔒  폴더 통째로 잠금(암호화) 프로그램  🔒         ║
║                                                          ║
║  ▸ 마스터 비밀번호 1개로 모든 폴더 잠금/해제             ║
║  ▸ Windows 탐색기 폴더 우클릭 → "🔒 폴더 잠금"           ║
║  ▸ 잠긴 폴더는 같은 위치에 '{폴더이름}.locked' 파일로    ║
║    남아 원래 자리에서 그대로 보임                        ║
║  ▸ .locked 파일을 더블클릭 → 비번 입력 → 즉시 해제       ║
║                                                          ║
║  ▸ PBKDF2-HMAC-SHA256 (480k회) 키 유도                   ║
║  ▸ Fernet (AES-128-CBC + HMAC-SHA256) 청크 암호화        ║
║  ▸ 4MB 청크 단위 스트리밍 처리 (대용량 지원)             ║
║  ▸ tkinter GUI                                           ║
╚══════════════════════════════════════════════════════════╝

저장 위치:
    ~/.folderlock/config.json   (마스터 비밀번호 검증값)
    잠긴 폴더는 원래 위치에 '{폴더이름}.locked' 파일로 저장됨

사전 준비:
    pip install cryptography

실행 방법:
    python folderLock.py                 # 홈 화면 (게이트 후)
    python folderLock.py <폴더 경로>      # 잠금 (우클릭 메뉴와 동일)
    python folderLock.py <.locked 파일>   # 해제 (더블클릭과 동일)
    python folderLock.py --register      # 우클릭 메뉴 + 파일 연결 등록 (Win)
    python folderLock.py --unregister    # 등록 해제 (Win)
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import shutil
import tarfile
import tempfile
import getpass
import platform
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Callable, Optional

# ── cryptography 라이브러리 임포트 (미설치 시 안내) ──────────────
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("=" * 55)
    print("  [오류] cryptography 라이브러리가 설치되어 있지 않습니다.")
    print("  아래 명령어로 설치한 후 다시 실행해 주세요:")
    print()
    print("      pip install cryptography")
    print("=" * 55)
    sys.exit(1)


# ════════════════════════════════════════════════════════════════
#  1. 상수 / 경로
# ════════════════════════════════════════════════════════════════

APP_HOME    = Path.home() / ".folderlock"
CONFIG_PATH = APP_HOME / "config.json"


def _hide_app_home_on_windows() -> None:
    """Windows에서 ~/.folderlock 폴더에 hidden 속성을 부여한다."""
    if sys.platform != "win32" or not APP_HOME.exists():
        return
    try:
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(str(APP_HOME), 0x02)
    except Exception:
        pass


# ════════════════════════════════════════════════════════════════
#  2. 사용자 정의 예외
# ════════════════════════════════════════════════════════════════

class WrongPasswordError(Exception):
    """비밀번호가 틀렸을 때"""


class FolderExistsError(Exception):
    """복원 대상 폴더가 이미 존재할 때"""


class NotInitializedError(Exception):
    """마스터 비밀번호가 아직 설정되지 않았을 때"""


class OriginalLocationMissingError(Exception):
    """헤더의 원본 위치가 더 이상 존재하지 않을 때 (호출자가 폴더 선택 다이얼로그로 fallback)"""


# ════════════════════════════════════════════════════════════════
#  3. CryptoEngine — 암호화/복호화 엔진
# ════════════════════════════════════════════════════════════════

class CryptoEngine:
    """
    폴더 ↔ .locked 파일 변환 엔진.

    파일 포맷 v2:
      [8B 매직 "FLOCK02\\x00"]
      [4B 헤더 JSON 길이]
      [헤더 JSON: salt, pw_check, iterations, folder_name,
                  original_parent, locked_at, version]
      [8B 청크 길이][암호화 청크] × N

    구버전 v1 ("FLOCK01\\x00") 도 읽기 호환.
    """

    LOCKED_EXT      = ".locked"
    KDF_ITERATIONS  = 480_000
    CHUNK_SIZE      = 4 * 1024 * 1024
    HEADER_MAGIC_V2 = b"FLOCK02\x00"
    HEADER_MAGIC_V1 = b"FLOCK01\x00"
    HEADER_FORMAT_VERSION = 2

    # ── 키 유도 ──────────────────────────────────────────────
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=CryptoEngine.KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @staticmethod
    def _make_pw_check(password: str, salt: bytes) -> str:
        """비밀번호 검증용 해시. 이 해시로 원본 비밀번호를 복원할 수 없음."""
        return hashlib.sha256(password.encode("utf-8") + salt).hexdigest()

    # ── 헤더 직렬화 ──────────────────────────────────────────
    @classmethod
    def _build_header(
        cls, password: str, salt: bytes,
        folder_name: str, original_parent: str,
    ) -> bytes:
        meta = {
            "version": cls.HEADER_FORMAT_VERSION,
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "pw_check": cls._make_pw_check(password, salt),
            "iterations": cls.KDF_ITERATIONS,
            "folder_name": folder_name,
            "original_parent": original_parent,
            "locked_at": datetime.now().isoformat(timespec="seconds"),
        }
        meta_bytes = json.dumps(meta, ensure_ascii=False).encode("utf-8")
        return cls.HEADER_MAGIC_V2 + len(meta_bytes).to_bytes(4, "big") + meta_bytes

    @classmethod
    def _parse_header(cls, f) -> dict:
        magic = f.read(8)
        if magic not in (cls.HEADER_MAGIC_V2, cls.HEADER_MAGIC_V1):
            raise ValueError("올바른 .locked 파일이 아닙니다.")
        meta_len = int.from_bytes(f.read(4), "big")
        meta_bytes = f.read(meta_len)
        return json.loads(meta_bytes.decode("utf-8"))

    @classmethod
    def peek_header(cls, locked_path: Path) -> dict:
        """파일을 복호화하지 않고 헤더 메타데이터만 읽는다."""
        with open(locked_path, "rb") as f:
            return cls._parse_header(f)

    # ═══════════════════════════════════════════════════════════
    #  잠금
    # ═══════════════════════════════════════════════════════════
    @classmethod
    def lock_folder(
        cls,
        folder: Path,
        password: str,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """
        폴더를 암호화하여 같은 위치에 '{폴더이름}.locked' 파일로 저장한다.
        원본 폴더는 삭제되고, 같은 자리에 .locked 파일이 남아 사용자
        시야에 그대로 보인다.

        같은 이름의 .locked 파일이 이미 있으면 FolderExistsError.
        """
        folder = Path(folder).resolve()
        if not folder.is_dir():
            raise FileNotFoundError(f"폴더를 찾을 수 없습니다: {folder}")

        locked_path = folder.parent / f"{folder.name}{cls.LOCKED_EXT}"
        if locked_path.exists():
            raise FolderExistsError(
                f"'{locked_path.name}' 파일이 이미 존재합니다.\n"
                f"위치: {locked_path.parent}\n"
                "기존 파일을 옮기거나 이름을 변경한 후 다시 시도하세요."
            )

        tmp_tar_fd, tmp_tar_path = tempfile.mkstemp(suffix=".tar")
        os.close(tmp_tar_fd)

        try:
            # 1) tar 아카이브 생성
            with tarfile.open(tmp_tar_path, "w") as tar:
                tar.add(str(folder), arcname=".")
            tar_size = os.path.getsize(tmp_tar_path)

            # 2) salt + 키 유도
            salt = secrets.token_bytes(16)
            key = cls._derive_key(password, salt)
            fernet = Fernet(key)

            # 3) 헤더 + 암호화 청크
            header = cls._build_header(
                password, salt, folder.name, str(folder.parent)
            )
            bytes_done = 0
            with open(tmp_tar_path, "rb") as fin, open(locked_path, "wb") as fout:
                fout.write(header)
                while True:
                    chunk = fin.read(cls.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted = fernet.encrypt(chunk)
                    fout.write(len(encrypted).to_bytes(8, "big"))
                    fout.write(encrypted)
                    bytes_done += len(chunk)
                    if progress_callback:
                        progress_callback(bytes_done, tar_size)

            # 4) 원본 폴더 삭제
            shutil.rmtree(folder)

        except Exception:
            if locked_path.exists():
                locked_path.unlink()
            raise
        finally:
            if os.path.exists(tmp_tar_path):
                os.unlink(tmp_tar_path)

        return locked_path

    # ═══════════════════════════════════════════════════════════
    #  해제
    # ═══════════════════════════════════════════════════════════
    @classmethod
    def unlock_folder(
        cls,
        locked_file: Path,
        password: str,
        restore_parent_override: Optional[Path] = None,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """
        .locked 파일을 복호화하여 원본 위치(또는 override)에 복원한다.
        성공 시 .locked 파일은 삭제된다.
        """
        locked_file = Path(locked_file).resolve()
        if not locked_file.is_file():
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {locked_file}")

        file_size = locked_file.stat().st_size
        tmp_tar_fd, tmp_tar_path = tempfile.mkstemp(suffix=".tar")
        os.close(tmp_tar_fd)

        try:
            with open(locked_file, "rb") as fin:
                meta = cls._parse_header(fin)
                salt = base64.urlsafe_b64decode(meta["salt"])
                folder_name = meta["folder_name"]

                if cls._make_pw_check(password, salt) != meta["pw_check"]:
                    raise WrongPasswordError("비밀번호가 일치하지 않습니다.")

                # 복원 위치 결정
                if restore_parent_override is not None:
                    restore_parent = Path(restore_parent_override)
                else:
                    op = meta.get("original_parent", "")
                    if op and Path(op).is_dir():
                        restore_parent = Path(op)
                    else:
                        raise OriginalLocationMissingError(
                            f"원본 위치를 찾을 수 없습니다: {op or '(헤더에 위치 정보 없음)'}"
                        )

                # 복호화 → 임시 tar
                key = cls._derive_key(password, salt)
                fernet = Fernet(key)
                bytes_done = fin.tell()

                with open(tmp_tar_path, "wb") as fout:
                    while True:
                        length_bytes = fin.read(8)
                        if not length_bytes or len(length_bytes) < 8:
                            break
                        chunk_len = int.from_bytes(length_bytes, "big")
                        encrypted_chunk = fin.read(chunk_len)
                        decrypted = fernet.decrypt(encrypted_chunk)
                        fout.write(decrypted)
                        bytes_done += 8 + chunk_len
                        if progress_callback:
                            progress_callback(bytes_done, file_size)

            # tar 추출
            restore_path = restore_parent / folder_name
            if restore_path.exists():
                raise FolderExistsError(
                    f"'{folder_name}' 폴더가 이미 존재합니다.\n"
                    f"위치: {restore_parent}\n"
                    "기존 폴더를 이동하거나 이름을 변경한 후 다시 시도하세요."
                )

            restore_path.mkdir(parents=True)
            with tarfile.open(tmp_tar_path, "r") as tar:
                # 경로 탈출 방지
                resolved_root = str(restore_path.resolve())
                for member in tar.getmembers():
                    member_path = (restore_path / member.name).resolve()
                    if not str(member_path).startswith(resolved_root):
                        raise ValueError(f"위험한 경로가 감지되었습니다: {member.name}")
                tar.extractall(path=str(restore_path))

            # .locked 파일 삭제
            locked_file.unlink()

        finally:
            if os.path.exists(tmp_tar_path):
                os.unlink(tmp_tar_path)

        return restore_path

# ════════════════════════════════════════════════════════════════
#  4. MasterPasswordStore — 마스터 비밀번호 저장/검증
# ════════════════════════════════════════════════════════════════

class MasterPasswordStore:
    """
    ~/.folderlock/config.json 관리.

    저장 항목:
      - salt        : 검증용 salt (랜덤 16B)
      - pw_check    : sha256(password + salt) 해시 (검증)
      - iterations  : PBKDF2 반복 횟수 (참고용)
      - enc_password: 마스터 비번을 기계 종속 키로 Fernet 암호화한 토큰
                      (드래그-잠금 시 비번 입력 없이 사용하기 위한 보관소;
                       다른 기기/사용자로 옮기면 복호화 불가)
    """

    CONFIG_VERSION = 1

    def __init__(self, config_path: Path = CONFIG_PATH):
        self.config_path = Path(config_path)

    # ── 기계 종속 obfuscation 키 ─────────────────────────────
    @staticmethod
    def _machine_key() -> bytes:
        seed = "|".join([
            platform.node(),       # 호스트명
            getpass.getuser(),     # 사용자명
            platform.system(),     # OS
            "folderlock-v1",       # 솔트 역할
        ])
        h = hashlib.sha256(seed.encode("utf-8")).digest()
        return base64.urlsafe_b64encode(h)

    @classmethod
    def _obfuscate(cls, password: str) -> str:
        return Fernet(cls._machine_key()).encrypt(password.encode("utf-8")).decode()

    @classmethod
    def _deobfuscate(cls, token: str) -> str:
        return Fernet(cls._machine_key()).decrypt(token.encode()).decode("utf-8")

    # ── 존재 확인 ────────────────────────────────────────────
    def exists(self) -> bool:
        return self.config_path.is_file()

    # ── 비밀번호 저장 ────────────────────────────────────────
    def set_password(self, password: str) -> None:
        salt = secrets.token_bytes(16)
        data = {
            "version": self.CONFIG_VERSION,
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "pw_check": CryptoEngine._make_pw_check(password, salt),
            "iterations": CryptoEngine.KDF_ITERATIONS,
            "enc_password": self._obfuscate(password),
        }
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        try:
            os.chmod(self.config_path, 0o600)
        except OSError:
            pass
        _hide_app_home_on_windows()

    # ── 비밀번호 검증 ────────────────────────────────────────
    def verify(self, password: str) -> bool:
        if not self.exists():
            return False
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        salt = base64.urlsafe_b64decode(data["salt"])
        return CryptoEngine._make_pw_check(password, salt) == data["pw_check"]

    # ── 저장된 비밀번호 복호화 (드래그-잠금용) ────────────────
    def get_password(self) -> str:
        if not self.exists():
            raise NotInitializedError("마스터 비밀번호가 설정되지 않았습니다.")
        with open(self.config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        try:
            return self._deobfuscate(data["enc_password"])
        except (InvalidToken, KeyError) as e:
            raise NotInitializedError(
                "저장된 비밀번호를 읽을 수 없습니다. config.json이 손상되었거나 "
                "다른 기기/사용자에서 옮겨진 것일 수 있습니다."
            ) from e


# ════════════════════════════════════════════════════════════════
#  5. WindowsIntegration — 탐색기 통합 (우클릭 메뉴 + 파일 연결)
# ════════════════════════════════════════════════════════════════

class WindowsIntegration:
    """
    Windows 탐색기 통합을 HKEY_CURRENT_USER 레지스트리에 등록한다.

      1) 폴더 우클릭 → "🔒 폴더 잠금"  → folderLock.py <folder>
      2) .locked 더블클릭             → folderLock.py <file>

    호출 시점의 Python 인터프리터(.venv 우선)와 folderLock.py 경로를
    레지스트리 명령에 그대로 embed한다. 프로젝트 폴더나 venv 위치를
    옮기면 다시 등록해야 한다.
    """

    FILE_TYPE_ID = "FolderLock.locked"
    MENU_KEY     = "FolderLock"
    MENU_LABEL   = "🔒 폴더 잠금"

    def __init__(self,
                 script_path: Optional[Path] = None,
                 python_exe: Optional[Path] = None):
        if sys.platform != "win32":
            raise NotImplementedError("Windows 전용 기능입니다.")
        self.script_path = Path(script_path or __file__).resolve()
        self.python_exe = Path(python_exe) if python_exe else self._detect_python_exe()

    def _detect_python_exe(self) -> Path:
        """
        레지스트리 명령에 박힐 Python 인터프리터를 결정한다.
        프로젝트 폴더에 .venv가 있으면 그 venv의 pythonw.exe를 최우선.
        """
        script_dir = self.script_path.parent
        for venv_name in (".venv", "venv"):
            pyw = script_dir / venv_name / "Scripts" / "pythonw.exe"
            py  = script_dir / venv_name / "Scripts" / "python.exe"
            if pyw.is_file():
                return pyw
            if py.is_file():
                return py
        cur = Path(sys.executable)
        pyw = cur.with_name("pythonw.exe")
        return pyw if pyw.exists() else cur

    def _command(self) -> str:
        return f'"{self.python_exe}" "{self.script_path}" "%1"'

    # ── 레지스트리 헬퍼 ──────────────────────────────────────
    @staticmethod
    def _set_key(path: str, value: str) -> None:
        import winreg
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, "", 0, winreg.REG_SZ, value)

    @staticmethod
    def _delete_key(path: str) -> None:
        import winreg
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except FileNotFoundError:
            pass

    # ── 등록 ─────────────────────────────────────────────────
    def register(self) -> None:
        cmd = self._command()

        # 1) 폴더 우클릭 메뉴
        menu = rf"Software\Classes\Directory\shell\{self.MENU_KEY}"
        self._set_key(menu, self.MENU_LABEL)
        self._set_key(rf"{menu}\command", cmd)

        # 2) .locked 파일 연결
        self._set_key(r"Software\Classes\.locked", self.FILE_TYPE_ID)
        self._set_key(rf"Software\Classes\{self.FILE_TYPE_ID}", "잠긴 폴더 (Folder Lock)")
        self._set_key(rf"Software\Classes\{self.FILE_TYPE_ID}\shell\open\command", cmd)

        # 탐색기 갱신
        try:
            import subprocess
            subprocess.run(
                ["ie4uinit.exe", "-show"],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

    # ── 등록 해제 ────────────────────────────────────────────
    def unregister(self) -> None:
        menu = rf"Software\Classes\Directory\shell\{self.MENU_KEY}"
        for path in [
            rf"{menu}\command",
            menu,
            rf"Software\Classes\{self.FILE_TYPE_ID}\shell\open\command",
            rf"Software\Classes\{self.FILE_TYPE_ID}\shell\open",
            rf"Software\Classes\{self.FILE_TYPE_ID}\shell",
            rf"Software\Classes\{self.FILE_TYPE_ID}",
            r"Software\Classes\.locked",
        ]:
            self._delete_key(path)


# ════════════════════════════════════════════════════════════════
#  7. UI 공통 테마
# ════════════════════════════════════════════════════════════════

class Theme:
    BG           = "#1e1e2e"
    BG_LIGHT     = "#2a2a3c"
    FG           = "#cdd6f4"
    ACCENT       = "#89b4fa"
    LOCK_COLOR   = "#f38ba8"
    UNLOCK_COLOR = "#a6e3a1"
    WARN_COLOR   = "#f9e2af"
    DIM          = "#6c7086"


def _center(win: tk.Misc, w: int, h: int) -> None:
    sx = (win.winfo_screenwidth() - w) // 2
    sy = (win.winfo_screenheight() - h) // 2
    win.geometry(f"{w}x{h}+{sx}+{sy}")


def _fmt_size(b: int) -> str:
    if b < 1024:      return f"{b} B"
    if b < 1024**2:   return f"{b/1024:.1f} KB"
    if b < 1024**3:   return f"{b/1024**2:.1f} MB"
    return f"{b/1024**3:.2f} GB"


# ════════════════════════════════════════════════════════════════
#  7. SetupDialog — 초기 비밀번호 설정
# ════════════════════════════════════════════════════════════════

class SetupDialog:
    """최초 실행 시 마스터 비밀번호를 설정한다."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self._setup_window()
        self._build_ui()

    def _setup_window(self):
        self.root.title("🔐 초기 설정")
        self.root.configure(bg=Theme.BG)
        self.root.resizable(False, False)
        _center(self.root, 460, 360)
        self.root.bind("<Return>", lambda e: self._on_save())
        self.root.bind("<Escape>", lambda e: self.root.destroy())

    def _build_ui(self):
        tk.Label(
            self.root, text="🔐 마스터 비밀번호 설정",
            font=("맑은 고딕", 16, "bold"),
            bg=Theme.BG, fg=Theme.ACCENT,
        ).pack(pady=(24, 4))
        tk.Label(
            self.root, text="이 비밀번호는 모든 폴더 잠금/해제에 사용됩니다",
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(0, 4))
        tk.Label(
            self.root, text="⚠ 분실 시 잠긴 폴더를 영원히 복구할 수 없습니다",
            font=("맑은 고딕", 9, "bold"), bg=Theme.BG, fg=Theme.WARN_COLOR,
        ).pack(pady=(0, 18))

        tk.Label(
            self.root, text="새 비밀번호 (4자 이상)",
            font=("맑은 고딕", 10, "bold"), bg=Theme.BG, fg=Theme.FG,
        ).pack(anchor="w", padx=40)
        self.pw1_var = tk.StringVar()
        self.pw1 = tk.Entry(
            self.root, textvariable=self.pw1_var,
            font=("맑은 고딕", 11), show="●",
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            insertbackground=Theme.FG, relief="flat",
        )
        self.pw1.pack(fill="x", padx=40, ipady=6, pady=(2, 10))

        tk.Label(
            self.root, text="비밀번호 확인",
            font=("맑은 고딕", 10, "bold"), bg=Theme.BG, fg=Theme.FG,
        ).pack(anchor="w", padx=40)
        self.pw2_var = tk.StringVar()
        self.pw2 = tk.Entry(
            self.root, textvariable=self.pw2_var,
            font=("맑은 고딕", 11), show="●",
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            insertbackground=Theme.FG, relief="flat",
        )
        self.pw2.pack(fill="x", padx=40, ipady=6, pady=(2, 18))

        btn_frame = tk.Frame(self.root, bg=Theme.BG)
        btn_frame.pack(pady=(0, 8))
        tk.Button(
            btn_frame, text="저장", font=("맑은 고딕", 12, "bold"),
            bg=Theme.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=10, command=self._on_save,
        ).pack(side="left", padx=8, ipady=6)
        tk.Button(
            btn_frame, text="취소", font=("맑은 고딕", 12),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=8, command=self.root.destroy,
        ).pack(side="left", padx=8, ipady=6)

        self.status_var = tk.StringVar(value="비밀번호를 입력하세요")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(4, 0))

        self.pw1.focus_set()

    def _on_save(self):
        pw1 = self.pw1_var.get()
        pw2 = self.pw2_var.get()
        if not pw1 or len(pw1) < 4:
            self.status_var.set("비밀번호는 4자 이상이어야 합니다.")
            return
        if pw1 != pw2:
            self.status_var.set("비밀번호가 일치하지 않습니다.")
            return
        try:
            MasterPasswordStore().set_password(pw1)
            messagebox.showinfo(
                "설정 완료",
                "마스터 비밀번호가 설정되었습니다.",
                parent=self.root,
            )
            # Windows에서는 바로 이어서 탐색기 통합 등록 제안
            if sys.platform == "win32":
                register_windows_integration_ui(parent=self.root, ask=True)
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("오류", f"저장 중 오류 발생:\n{e}", parent=self.root)


# ════════════════════════════════════════════════════════════════
#  8. UnlockGateDialog — 더블클릭 후 비밀번호 게이트
# ════════════════════════════════════════════════════════════════

class UnlockGateDialog:
    """비밀번호 검증 후 on_success(password) 콜백을 호출한다."""

    def __init__(self, root: tk.Tk, on_success: Callable[[str], None]):
        self.root = root
        self.on_success = on_success
        self._setup_window()
        self._build_ui()

    def _setup_window(self):
        self.root.title("🔐 잠금 해제")
        self.root.configure(bg=Theme.BG)
        self.root.resizable(False, False)
        _center(self.root, 420, 260)
        self.root.bind("<Return>", lambda e: self._on_enter())
        self.root.bind("<Escape>", lambda e: self.root.destroy())

    def _build_ui(self):
        tk.Label(
            self.root, text="🔐 마스터 비밀번호",
            font=("맑은 고딕", 16, "bold"),
            bg=Theme.BG, fg=Theme.ACCENT,
        ).pack(pady=(30, 4))
        tk.Label(
            self.root, text="잠긴 항목을 보려면 비밀번호를 입력하세요",
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(0, 18))

        pw_row = tk.Frame(self.root, bg=Theme.BG)
        pw_row.pack(fill="x", padx=30)
        self.pw_var = tk.StringVar()
        self._show = False
        self.pw_entry = tk.Entry(
            pw_row, textvariable=self.pw_var,
            font=("맑은 고딕", 12), show="●",
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            insertbackground=Theme.FG, relief="flat",
        )
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=7)
        tk.Button(
            pw_row, text="👁", font=("맑은 고딕", 11),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            relief="flat", cursor="hand2", width=3,
            command=self._toggle,
        ).pack(side="right", padx=(4, 0), ipady=5)
        self.pw_entry.focus_set()

        btn_frame = tk.Frame(self.root, bg=Theme.BG)
        btn_frame.pack(pady=(18, 0))
        tk.Button(
            btn_frame, text="확인", font=("맑은 고딕", 12, "bold"),
            bg=Theme.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=10, command=self._on_enter,
        ).pack(side="left", padx=8, ipady=6)
        tk.Button(
            btn_frame, text="취소", font=("맑은 고딕", 12),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=8, command=self.root.destroy,
        ).pack(side="left", padx=8, ipady=6)

        self.status_var = tk.StringVar(value="비밀번호를 입력하세요")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(10, 0))

    def _toggle(self):
        self._show = not self._show
        self.pw_entry.config(show="" if self._show else "●")

    def _on_enter(self):
        pw = self.pw_var.get()
        if not pw:
            self.status_var.set("비밀번호를 입력하세요")
            return
        if MasterPasswordStore().verify(pw):
            self.on_success(pw)
        else:
            self.pw_var.set("")
            self.status_var.set("비밀번호가 일치하지 않습니다")


# ════════════════════════════════════════════════════════════════
#  9. UnlockMainApp — 메인 UI (잠긴 항목 목록 + 해제 + 비번 수정)
# ════════════════════════════════════════════════════════════════

class UnlockMainApp:
    """게이트 통과 후 표시되는 홈 화면 — 잠금/해제/설정 액션."""

    def __init__(self, root: tk.Tk, master_password: str):
        self.root = root
        self.password = master_password
        self._setup_window()
        self._build_ui()

    def _setup_window(self):
        self.root.title("🔒 Folder Lock")
        self.root.configure(bg=Theme.BG)
        self.root.resizable(False, False)
        _center(self.root, 500, 420)

    def _build_ui(self):
        tk.Label(
            self.root, text="🔒 Folder Lock",
            font=("맑은 고딕", 20, "bold"),
            bg=Theme.BG, fg=Theme.ACCENT,
        ).pack(pady=(28, 4))
        tk.Label(
            self.root, text="폴더를 잠그면 같은 위치에 .locked 파일이 만들어지고,",
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack()
        tk.Label(
            self.root, text="더블클릭하면 비밀번호로 바로 해제할 수 있습니다.",
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(0, 22))

        # ── 주요 액션 버튼 ────────────────────────────────────
        actions = tk.Frame(self.root, bg=Theme.BG)
        actions.pack(pady=(0, 18))
        tk.Button(
            actions, text="🔒  폴더 선택해서 잠그기",
            font=("맑은 고딕", 12, "bold"),
            bg=Theme.LOCK_COLOR, fg="#1e1e2e",
            activebackground="#f7a5bc", relief="flat",
            cursor="hand2", width=24, command=self._on_lock_folder,
        ).pack(pady=4, ipady=8)
        tk.Button(
            actions, text="🔓  .locked 파일 선택해서 풀기",
            font=("맑은 고딕", 12, "bold"),
            bg=Theme.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=24, command=self._on_unlock_file,
        ).pack(pady=4, ipady=8)

        # ── 하단: 우클릭 메뉴 등록 / 비밀번호 수정 ────────────
        bottom = tk.Frame(self.root, bg=Theme.BG)
        bottom.pack(side="bottom", pady=(0, 18))
        tk.Button(
            bottom, text="🔧  우클릭 메뉴 등록",
            font=("맑은 고딕", 10),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=18, command=self._on_register_integration,
        ).pack(side="left", padx=4, ipady=6)
        tk.Button(
            bottom, text="⚙  비밀번호 수정",
            font=("맑은 고딕", 10),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=16, command=self._on_change_pw,
        ).pack(side="left", padx=4, ipady=6)

    # ── 잠금 ─────────────────────────────────────────────────
    def _on_lock_folder(self):
        chosen = filedialog.askdirectory(
            title="잠글 폴더를 선택하세요", parent=self.root,
        )
        if not chosen:
            return
        lock_folders_silent([Path(chosen)], parent=self.root)

    # ── 해제 ─────────────────────────────────────────────────
    def _on_unlock_file(self):
        chosen = filedialog.askopenfilename(
            title="해제할 .locked 파일을 선택하세요",
            parent=self.root,
            filetypes=[("Locked files", "*.locked"), ("All files", "*.*")],
        )
        if not chosen:
            return
        unlock_external(self.password, [Path(chosen)], parent=self.root)

    # ── 비밀번호 수정 ────────────────────────────────────────
    def _on_change_pw(self):
        dlg = tk.Toplevel(self.root)
        ChangePasswordDialog(dlg, self.password, on_done=self._on_pw_changed)

    def _on_pw_changed(self, new_password: str):
        self.password = new_password

    # ── Windows 우클릭 메뉴 등록 ─────────────────────────────
    def _on_register_integration(self):
        register_windows_integration_ui(parent=self.root, ask=True)


# ════════════════════════════════════════════════════════════════
#  10. ChangePasswordDialog — 비밀번호 수정 + vault 재암호화
# ════════════════════════════════════════════════════════════════

class ChangePasswordDialog:
    def __init__(
        self,
        root: tk.Toplevel,
        current_password: str,
        on_done: Callable[[str], None],
    ):
        self.root = root
        self.current_password = current_password
        self.on_done = on_done
        self._setup_window()
        self._build_ui()

    def _setup_window(self):
        self.root.title("⚙ 비밀번호 수정")
        self.root.configure(bg=Theme.BG)
        self.root.resizable(False, False)
        _center(self.root, 460, 380)
        self.root.transient(self.root.master)
        self.root.grab_set()
        self.root.bind("<Escape>", lambda e: self.root.destroy())

    def _build_ui(self):
        tk.Label(
            self.root, text="⚙ 비밀번호 수정",
            font=("맑은 고딕", 16, "bold"),
            bg=Theme.BG, fg=Theme.ACCENT,
        ).pack(pady=(20, 4))
        tk.Label(
            self.root, text="이미 잠긴 .locked 파일은 이전 비밀번호로만 해제할 수 있습니다",
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.WARN_COLOR,
        ).pack(pady=(0, 18))

        tk.Label(
            self.root, text="새 비밀번호 (4자 이상)",
            font=("맑은 고딕", 10, "bold"), bg=Theme.BG, fg=Theme.FG,
        ).pack(anchor="w", padx=40)
        self.pw1_var = tk.StringVar()
        self.pw1 = tk.Entry(
            self.root, textvariable=self.pw1_var,
            font=("맑은 고딕", 11), show="●",
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            insertbackground=Theme.FG, relief="flat",
        )
        self.pw1.pack(fill="x", padx=40, ipady=6, pady=(2, 10))

        tk.Label(
            self.root, text="비밀번호 확인",
            font=("맑은 고딕", 10, "bold"), bg=Theme.BG, fg=Theme.FG,
        ).pack(anchor="w", padx=40)
        self.pw2_var = tk.StringVar()
        self.pw2 = tk.Entry(
            self.root, textvariable=self.pw2_var,
            font=("맑은 고딕", 11), show="●",
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            insertbackground=Theme.FG, relief="flat",
        )
        self.pw2.pack(fill="x", padx=40, ipady=6, pady=(2, 14))

        self.status_var = tk.StringVar(value="새 비밀번호를 입력하세요")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(2, 12))

        btn_frame = tk.Frame(self.root, bg=Theme.BG)
        btn_frame.pack()
        self.save_btn = tk.Button(
            btn_frame, text="저장",
            font=("맑은 고딕", 11, "bold"),
            bg=Theme.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=10, command=self._on_save,
        )
        self.save_btn.pack(side="left", padx=8, ipady=6)
        self.cancel_btn = tk.Button(
            btn_frame, text="취소", font=("맑은 고딕", 11),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=8, command=self.root.destroy,
        )
        self.cancel_btn.pack(side="left", padx=8, ipady=6)

        self.pw1.focus_set()

    def _on_save(self):
        pw1 = self.pw1_var.get()
        pw2 = self.pw2_var.get()
        if not pw1 or len(pw1) < 4:
            self.status_var.set("비밀번호는 4자 이상이어야 합니다.")
            return
        if pw1 != pw2:
            self.status_var.set("비밀번호가 일치하지 않습니다.")
            return
        if pw1 == self.current_password:
            self.status_var.set("현재 비밀번호와 동일합니다.")
            return

        try:
            MasterPasswordStore().set_password(pw1)
            messagebox.showinfo(
                "완료",
                "비밀번호가 변경되었습니다.\n\n"
                "⚠ 이미 잠긴 .locked 파일은 새 비밀번호로 자동 변환되지 않습니다.\n"
                "기존 파일을 해제하려면 이전 비밀번호가 필요합니다.",
                parent=self.root,
            )
            self.on_done(pw1)
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("오류", f"오류 발생:\n{e}", parent=self.root)


# ════════════════════════════════════════════════════════════════
#  11. 드래그 잠금 (UI 없이 한 번에 처리)
# ════════════════════════════════════════════════════════════════

def lock_folders_silent(folders: list, parent: Optional[tk.Tk] = None) -> None:
    """드래그된 폴더(들)를 저장된 마스터 비번으로 잠근다."""
    store = MasterPasswordStore()
    try:
        password = store.get_password()
    except NotInitializedError as e:
        messagebox.showerror(
            "오류",
            f"{e}\n\n프로그램을 다시 실행하여 초기 설정을 진행해 주세요.",
            parent=parent,
        )
        return

    successes = []  # (folder_path, locked_path)
    failures = []
    for f in folders:
        f = Path(f).resolve()
        if not f.is_dir():
            failures.append((f, "폴더가 아닙니다"))
            continue
        try:
            locked_path = CryptoEngine.lock_folder(f, password)
            successes.append((f, locked_path))
        except Exception as e:
            failures.append((f, str(e)))

    if successes and not failures:
        if len(successes) == 1:
            f, lp = successes[0]
            messagebox.showinfo(
                "잠금 완료",
                f"'{f.name}' 폴더가 잠겼습니다.\n\n"
                f"  파일: {lp.name}\n"
                f"  위치: {lp.parent}\n\n"
                "해제하려면 .locked 파일을 더블클릭하세요.",
                parent=parent,
            )
        else:
            names = "\n".join(f"  ▸ {lp.name}" for _, lp in successes)
            messagebox.showinfo(
                "잠금 완료",
                f"{len(successes)}개 폴더가 잠겼습니다:\n\n{names}",
                parent=parent,
            )
    elif failures and not successes:
        msgs = "\n".join(f"  ▸ {f.name}: {e}" for f, e in failures)
        messagebox.showerror("잠금 실패", f"잠금에 실패했습니다:\n\n{msgs}", parent=parent)
    else:
        s = "\n".join(f"  ✓ {f.name}" for f, _ in successes)
        fl = "\n".join(f"  ✗ {p.name}: {e}" for p, e in failures)
        messagebox.showwarning(
            "부분 완료",
            f"성공:\n{s}\n\n실패:\n{fl}",
            parent=parent,
        )


# ════════════════════════════════════════════════════════════════
#  12. .locked 파일 해제 (드래그/더블클릭/파일 선택 공용)
# ════════════════════════════════════════════════════════════════

def unlock_external(password: str, locked_files: list, parent: Optional[tk.Tk] = None) -> None:
    """주어진 .locked 파일(들)을 비번으로 해제 시도한다."""
    ok = []
    bad = []
    for lf in locked_files:
        lf = Path(lf).resolve()
        try:
            rp = CryptoEngine.unlock_folder(lf, password)
            ok.append(rp)
        except OriginalLocationMissingError as e:
            ans = messagebox.askyesno(
                "원본 위치 없음",
                f"{e}\n\n{lf.name}의 복원 위치를 직접 선택하시겠습니까?",
                parent=parent,
            )
            if ans:
                chosen = filedialog.askdirectory(
                    title=f"{lf.name} 복원 위치 선택", parent=parent
                )
                if chosen:
                    try:
                        rp = CryptoEngine.unlock_folder(
                            lf, password, restore_parent_override=Path(chosen)
                        )
                        ok.append(rp)
                    except Exception as ex:
                        bad.append((lf, str(ex)))
                else:
                    bad.append((lf, "취소됨"))
            else:
                bad.append((lf, "취소됨"))
        except Exception as e:
            bad.append((lf, str(e)))

    if ok and not bad:
        names = "\n".join(f"  ▸ {rp.name}" for rp in ok)
        messagebox.showinfo("해제 완료", f"{len(ok)}개 폴더가 복원되었습니다:\n\n{names}", parent=parent)
    elif bad and not ok:
        msgs = "\n".join(f"  ▸ {lf.name}: {e}" for lf, e in bad)
        messagebox.showerror("해제 실패", f"해제에 실패했습니다:\n\n{msgs}", parent=parent)
    elif ok and bad:
        s = "\n".join(f"  ✓ {rp.name}" for rp in ok)
        fl = "\n".join(f"  ✗ {lf.name}: {e}" for lf, e in bad)
        messagebox.showwarning("부분 완료", f"성공:\n{s}\n\n실패:\n{fl}", parent=parent)


# ════════════════════════════════════════════════════════════════
#  13. Windows 통합 등록 UI 헬퍼
# ════════════════════════════════════════════════════════════════

def register_windows_integration_ui(parent: Optional[tk.Misc] = None, ask: bool = True) -> bool:
    """
    Windows 탐색기 통합(우클릭 메뉴 + .locked 파일 연결)을 등록한다.
    ask=True면 먼저 yes/no 다이얼로그. 성공 시 True.

    Windows가 아니면 안내 후 False.
    """
    if sys.platform != "win32":
        if ask:
            messagebox.showinfo(
                "Windows 전용 기능",
                "탐색기 우클릭 메뉴 등록은 Windows에서만 동작합니다.\n"
                "이 OS에서는 메인 화면의 '🔒 폴더 선택해서 잠그기' 버튼이나\n"
                "CLI(`python folderLock.py <폴더>`)로 잠금을 실행하세요.",
                parent=parent,
            )
        return False

    if ask:
        ans = messagebox.askyesno(
            "Windows 통합 등록",
            "탐색기에 다음을 등록할까요?\n\n"
            "  ▸ 폴더 우클릭 → \"🔒 폴더 잠금\"\n"
            "  ▸ .locked 파일 더블클릭 → 자동 해제\n\n"
            "(현재 Python 경로와 folderLock.py 위치가 레지스트리에\n"
            " 박힙니다. 프로젝트 폴더나 가상환경을 옮기면 다시\n"
            " 등록해야 합니다.)",
            parent=parent,
        )
        if not ans:
            return False

    try:
        WindowsIntegration().register()
        messagebox.showinfo(
            "등록 완료",
            "탐색기 통합이 등록되었습니다.\n\n"
            "  ▸ 폴더를 우클릭하면 \"🔒 폴더 잠금\" 메뉴가 보입니다\n"
            "  ▸ .locked 파일을 더블클릭하면 비번 입력 후 해제됩니다",
            parent=parent,
        )
        return True
    except Exception as e:
        messagebox.showerror(
            "등록 실패",
            f"레지스트리 등록 중 오류가 발생했습니다:\n{e}",
            parent=parent,
        )
        return False


# ════════════════════════════════════════════════════════════════
#  14. 메인 엔트리포인트
# ════════════════════════════════════════════════════════════════

def main():
    # ── CLI: Windows 탐색기 통합 등록/해제 (GUI 없이) ──────────
    if "--register" in sys.argv:
        try:
            WindowsIntegration().register()
            print("✓ Windows 탐색기 통합이 등록되었습니다.")
        except Exception as e:
            print(f"✗ 등록 실패: {e}")
            sys.exit(1)
        return

    if "--unregister" in sys.argv:
        try:
            WindowsIntegration().unregister()
            print("✓ Windows 탐색기 통합이 제거되었습니다.")
        except Exception as e:
            print(f"✗ 제거 실패: {e}")
            sys.exit(1)
        return

    root = tk.Tk()
    root.withdraw()

    store = MasterPasswordStore()

    # ── (A) 마스터 비번 미설정 → 초기 설정만 진행 ─────────────
    if not store.exists():
        root.deiconify()
        SetupDialog(root)
        root.mainloop()
        return

    # ── (B) 인자 분기:
    #        폴더    → 잠금 (탐색기 우클릭 → "🔒 폴더 잠금")
    #        .locked → 해제 (탐색기 더블클릭)
    #        없음    → 홈 화면 (게이트 → UnlockMainApp)
    folders_from_args = []
    locked_from_args = []

    for a in sys.argv[1:]:
        p = Path(a).resolve()
        if p.is_dir():
            folders_from_args.append(p)
        elif p.is_file() and p.suffix == CryptoEngine.LOCKED_EXT:
            locked_from_args.append(p)

    def transition_to_gate(after_success: Callable[[str], None]):
        """Gate 표시 후 검증 통과 시 after_success(pw)."""
        root.deiconify()
        UnlockGateDialog(root, after_success)

    def transition_to_main_app(password: str):
        """Gate를 메인 UI로 교체."""
        for w in root.winfo_children():
            w.destroy()
        root.unbind("<Return>")
        root.unbind("<Escape>")
        UnlockMainApp(root, password)

    def handle_locked_external(locked_paths: list):
        def after_pw(pw: str):
            for w in root.winfo_children():
                w.destroy()
            root.unbind("<Return>")
            root.unbind("<Escape>")
            root.withdraw()
            unlock_external(pw, locked_paths, parent=root)
            root.destroy()
        transition_to_gate(after_pw)

    if folders_from_args:
        lock_folders_silent(folders_from_args, parent=root)
        root.destroy()
    elif locked_from_args:
        handle_locked_external(locked_from_args)
    else:
        transition_to_gate(transition_to_main_app)

    root.mainloop()


if __name__ == "__main__":
    main()
