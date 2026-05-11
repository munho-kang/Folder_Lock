#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║        🔒  폴더 통째로 잠금(암호화) 프로그램  🔒         ║
║                                                          ║
║  ▸ 마스터 비밀번호 1개로 모든 폴더 잠금/해제             ║
║  ▸ 폴더를 이 파일에 드래그하면 자동 잠금 (입력 없음)     ║
║  ▸ 잠긴 폴더는 사라지고, .locked 파일은 숨김 vault에     ║
║    저장되어 사용자 시야에서 보이지 않음                  ║
║  ▸ 더블클릭 → 비번 입력 → 잠긴 항목 목록 → 해제          ║
║  ▸ 비밀번호 수정 시 vault 내 모든 항목 자동 재암호화     ║
║                                                          ║
║  ▸ PBKDF2-HMAC-SHA256 (480k회) 키 유도                   ║
║  ▸ Fernet (AES-128-CBC + HMAC-SHA256) 청크 암호화        ║
║  ▸ 4MB 청크 단위 스트리밍 처리 (대용량 지원)             ║
║  ▸ tkinter GUI                                           ║
╚══════════════════════════════════════════════════════════╝

저장 위치:
    ~/.folderlock/config.json   (마스터 비밀번호 검증값)
    ~/.folderlock/vault/        (잠긴 .locked 파일들)

사전 준비:
    pip install cryptography

실행 방법:
    python folderLock.py                # 더블클릭과 동일 (해제 모드)
    python folderLock.py <폴더 경로>     # 잠금 (드래그와 동일)
"""

import os
import sys
import json
import uuid
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
VAULT_DIR   = APP_HOME / "vault"


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
        vault_dir: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> Path:
        """
        폴더를 암호화하여 vault 내에 UUID 파일명으로 저장한다.
        원본 폴더는 삭제된다. 헤더에는 원본 위치(parent)가 기록되어
        해제 시 자동 복원에 사용된다.
        """
        folder = Path(folder).resolve()
        if not folder.is_dir():
            raise FileNotFoundError(f"폴더를 찾을 수 없습니다: {folder}")

        vault_dir = Path(vault_dir)
        vault_dir.mkdir(parents=True, exist_ok=True)
        locked_path = vault_dir / f"{uuid.uuid4().hex}{cls.LOCKED_EXT}"

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

    # ═══════════════════════════════════════════════════════════
    #  재암호화 (비밀번호 수정 시 사용)
    # ═══════════════════════════════════════════════════════════
    @classmethod
    def reencrypt_file(
        cls,
        locked_file: Path,
        old_password: str,
        new_password: str,
    ) -> None:
        """
        .locked 파일을 기존 비번으로 복호화한 뒤 새 비번으로 다시 암호화한다.
        원본 폴더 위치/이름/잠근 시간 같은 메타데이터는 보존한다.
        새 파일은 임시 경로에 만든 후 원자적으로 교체한다.
        """
        locked_file = Path(locked_file)
        tmp_out  = locked_file.with_suffix(".locked.tmp")
        tmp_tar_fd, tmp_tar_path = tempfile.mkstemp(suffix=".tar")
        os.close(tmp_tar_fd)

        try:
            # 1) 복호화 → 임시 tar
            with open(locked_file, "rb") as fin:
                meta = cls._parse_header(fin)
                old_salt = base64.urlsafe_b64decode(meta["salt"])
                if cls._make_pw_check(old_password, old_salt) != meta["pw_check"]:
                    raise WrongPasswordError(
                        f"파일을 이전 비밀번호로 열 수 없습니다: {locked_file.name}"
                    )
                old_fernet = Fernet(cls._derive_key(old_password, old_salt))

                with open(tmp_tar_path, "wb") as fout:
                    while True:
                        length_bytes = fin.read(8)
                        if not length_bytes or len(length_bytes) < 8:
                            break
                        chunk_len = int.from_bytes(length_bytes, "big")
                        encrypted_chunk = fin.read(chunk_len)
                        decrypted = old_fernet.decrypt(encrypted_chunk)
                        fout.write(decrypted)

            # 2) 새 salt/키로 재암호화 → 임시 출력
            new_salt = secrets.token_bytes(16)
            new_fernet = Fernet(cls._derive_key(new_password, new_salt))

            new_meta = {
                "version": cls.HEADER_FORMAT_VERSION,
                "salt": base64.urlsafe_b64encode(new_salt).decode(),
                "pw_check": cls._make_pw_check(new_password, new_salt),
                "iterations": cls.KDF_ITERATIONS,
                "folder_name": meta.get("folder_name", ""),
                "original_parent": meta.get("original_parent", ""),
                "locked_at": meta.get("locked_at", datetime.now().isoformat(timespec="seconds")),
            }
            new_meta_bytes = json.dumps(new_meta, ensure_ascii=False).encode("utf-8")

            with open(tmp_tar_path, "rb") as fin, open(tmp_out, "wb") as fout:
                fout.write(cls.HEADER_MAGIC_V2)
                fout.write(len(new_meta_bytes).to_bytes(4, "big"))
                fout.write(new_meta_bytes)
                while True:
                    chunk = fin.read(cls.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted = new_fernet.encrypt(chunk)
                    fout.write(len(encrypted).to_bytes(8, "big"))
                    fout.write(encrypted)

            # 3) 원자적 교체
            os.replace(tmp_out, locked_file)

        finally:
            if os.path.exists(tmp_tar_path):
                os.unlink(tmp_tar_path)
            if tmp_out.exists():
                try:
                    tmp_out.unlink()
                except OSError:
                    pass


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
#  5. VaultManager — vault 디렉토리 관리
# ════════════════════════════════════════════════════════════════

class VaultManager:
    """~/.folderlock/vault/ 안의 .locked 파일들을 관리한다."""

    def __init__(self, vault_dir: Path = VAULT_DIR):
        self.vault_dir = Path(vault_dir)
        self.vault_dir.mkdir(parents=True, exist_ok=True)
        # Windows에서는 .폴더가 자동으로 숨겨지지 않으므로 hidden 속성 부여
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.kernel32.SetFileAttributesW(
                    str(self.vault_dir.parent), 0x02  # FILE_ATTRIBUTE_HIDDEN
                )
            except Exception:
                pass

    def list_items(self) -> list:
        """vault 내 모든 .locked 파일의 메타데이터를 반환한다."""
        items = []
        for f in sorted(self.vault_dir.glob(f"*{CryptoEngine.LOCKED_EXT}")):
            try:
                meta = CryptoEngine.peek_header(f)
                items.append({
                    "path": f,
                    "folder_name": meta.get("folder_name", "(이름 없음)"),
                    "original_parent": meta.get("original_parent", ""),
                    "locked_at": meta.get("locked_at", ""),
                    "size": f.stat().st_size,
                })
            except Exception:
                items.append({
                    "path": f,
                    "folder_name": "(읽을 수 없음)",
                    "original_parent": "",
                    "locked_at": "",
                    "size": f.stat().st_size,
                })
        return items

    def reencrypt_all(
        self,
        old_password: str,
        new_password: str,
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
    ) -> None:
        items = list(self.vault_dir.glob(f"*{CryptoEngine.LOCKED_EXT}"))
        total = len(items)
        for i, item in enumerate(items, 1):
            CryptoEngine.reencrypt_file(item, old_password, new_password)
            if progress_callback:
                progress_callback(i, total, item.name)


# ════════════════════════════════════════════════════════════════
#  6. LauncherInstaller — 바탕화면 드래그-앤-드롭 런처 생성
# ════════════════════════════════════════════════════════════════

class LauncherInstaller:
    """
    바탕화면에 드래그-앤-드롭 런처를 만든다.

    ▸ macOS  : ~/Applications/FolderLock.app  (Info.plist + bash launcher)
               (~/Desktop은 iCloud Drive 동기화로 권한 문제가 잦아 피함)
    ▸ Windows: ~/Desktop/FolderLock.bat       (pythonw.exe 호출)
    ▸ Linux  : ~/Desktop/FolderLock.desktop

    런처는 호출 시점의 Python 인터프리터(sys.executable)와 folderLock.py
    경로를 그대로 embed한다. 프로젝트 폴더나 venv 위치를 옮기면 런처를
    다시 만들어야 한다.
    """

    APP_NAME = "FolderLock"

    def __init__(self,
                 script_path: Optional[Path] = None,
                 python_exe: Optional[Path] = None):
        self.script_path = Path(script_path or __file__).resolve()
        # symlink를 따라가지 않는다 (.venv → 시스템 Python으로 새지 않도록)
        self.python_exe = Path(python_exe) if python_exe else self._detect_python_exe()

    def _detect_python_exe(self) -> Path:
        """
        런처가 호출할 Python 인터프리터를 결정한다.
        프로젝트 폴더에 .venv가 있으면 그 venv의 Python을 최우선으로 사용.
        그 외에는 현재 sys.executable을 그대로 (symlink 보존).
        """
        script_dir = self.script_path.parent
        for venv_name in (".venv", "venv"):
            if sys.platform == "win32":
                pyw = script_dir / venv_name / "Scripts" / "pythonw.exe"
                py  = script_dir / venv_name / "Scripts" / "python.exe"
                if pyw.is_file():
                    return pyw
                if py.is_file():
                    return py
            else:
                py = script_dir / venv_name / "bin" / "python"
                if py.is_file():
                    return py
        return Path(sys.executable)

    @staticmethod
    def _install_dir() -> Path:
        """
        런처를 설치할 디렉토리.
        macOS는 ~/Applications (iCloud Drive 동기화 Desktop의 권한 문제를 피함).
        다른 OS는 바탕화면.
        """
        if sys.platform == "darwin":
            return Path.home() / "Applications"
        return Path.home() / "Desktop"

    @staticmethod
    def install_dir_label() -> str:
        """UI 표시용 위치 라벨."""
        if sys.platform == "darwin":
            return "응용 프로그램(Applications) 폴더"
        return "바탕화면(Desktop)"

    # ── 플랫폼 분기 ──────────────────────────────────────────
    def install(self) -> Path:
        target = self._install_dir()
        target.mkdir(parents=True, exist_ok=True)

        if sys.platform == "darwin":
            return self._install_macos(target)
        if sys.platform == "win32":
            return self._install_windows(target)
        return self._install_linux(target)

    # ── macOS .app 번들 ─────────────────────────────────────
    def _install_macos(self, target: Path) -> Path:
        app_path = target / f"{self.APP_NAME}.app"
        if app_path.exists():
            shutil.rmtree(app_path)

        contents = app_path / "Contents"
        macos_dir = contents / "MacOS"
        resources = contents / "Resources"
        macos_dir.mkdir(parents=True)
        resources.mkdir(parents=True)

        plist = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
            '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n'
            '<dict>\n'
            '    <key>CFBundleExecutable</key>\n'
            '    <string>launcher</string>\n'
            '    <key>CFBundleIdentifier</key>\n'
            '    <string>com.folderlock.app</string>\n'
            f'    <key>CFBundleName</key>\n'
            f'    <string>{self.APP_NAME}</string>\n'
            '    <key>CFBundleDisplayName</key>\n'
            '    <string>🔒 Folder Lock</string>\n'
            '    <key>CFBundleShortVersionString</key>\n'
            '    <string>1.0</string>\n'
            '    <key>CFBundleVersion</key>\n'
            '    <string>1</string>\n'
            '    <key>CFBundlePackageType</key>\n'
            '    <string>APPL</string>\n'
            '    <key>LSMinimumSystemVersion</key>\n'
            '    <string>10.13</string>\n'
            '    <key>NSHighResolutionCapable</key>\n'
            '    <true/>\n'
            '    <key>CFBundleDocumentTypes</key>\n'
            '    <array>\n'
            '        <dict>\n'
            '            <key>CFBundleTypeName</key>\n'
            '            <string>Folder</string>\n'
            '            <key>CFBundleTypeRole</key>\n'
            '            <string>Editor</string>\n'
            '            <key>LSItemContentTypes</key>\n'
            '            <array>\n'
            '                <string>public.folder</string>\n'
            '                <string>public.directory</string>\n'
            '            </array>\n'
            '            <key>LSHandlerRank</key>\n'
            '            <string>Alternate</string>\n'
            '        </dict>\n'
            '        <dict>\n'
            '            <key>CFBundleTypeName</key>\n'
            '            <string>Locked Folder</string>\n'
            '            <key>CFBundleTypeExtensions</key>\n'
            '            <array>\n'
            '                <string>locked</string>\n'
            '            </array>\n'
            '            <key>CFBundleTypeRole</key>\n'
            '            <string>Editor</string>\n'
            '            <key>LSHandlerRank</key>\n'
            '            <string>Owner</string>\n'
            '        </dict>\n'
            '    </array>\n'
            '</dict>\n'
            '</plist>\n'
        )
        (contents / "Info.plist").write_text(plist, encoding="utf-8")

        launcher = (
            "#!/bin/bash\n"
            f'exec "{self.python_exe}" "{self.script_path}" "$@"\n'
        )
        launcher_path = macos_dir / "launcher"
        launcher_path.write_text(launcher, encoding="utf-8")
        launcher_path.chmod(0o755)

        # quarantine 속성 제거 (혹시 붙어 있을 경우)
        try:
            import subprocess
            subprocess.run(
                ["xattr", "-dr", "com.apple.quarantine", str(app_path)],
                capture_output=True, timeout=5,
            )
        except Exception:
            pass

        return app_path

    # ── Windows .bat ─────────────────────────────────────────
    def _install_windows(self, target: Path) -> Path:
        bat_path = target / f"{self.APP_NAME}.bat"

        # 콘솔 창 없이 실행되도록 pythonw.exe를 우선 사용
        pythonw = self.python_exe.with_name("pythonw.exe")
        py = pythonw if pythonw.exists() else self.python_exe

        content = (
            "@echo off\r\n"
            f'"{py}" "{self.script_path}" %*\r\n'
        )
        bat_path.write_text(content, encoding="utf-8")
        return bat_path

    # ── Linux .desktop ───────────────────────────────────────
    def _install_linux(self, target: Path) -> Path:
        desktop_file = target / f"{self.APP_NAME}.desktop"
        content = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=Folder Lock\n"
            "Comment=폴더를 드래그하여 잠금\n"
            f"Exec={self.python_exe} {self.script_path} %F\n"
            "Terminal=false\n"
            "Categories=Utility;\n"
            "MimeType=inode/directory;\n"
        )
        desktop_file.write_text(content, encoding="utf-8")
        desktop_file.chmod(0o755)
        return desktop_file


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
            # 바로 이어서 런처 설치 제안
            install_launcher_ui(parent=self.root, ask=True)
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
    """게이트 통과 후 표시되는 vault 관리 화면."""

    def __init__(self, root: tk.Tk, master_password: str):
        self.root = root
        self.password = master_password
        self.vault = VaultManager()
        self._setup_window()
        self._build_ui()
        self._refresh()

    def _setup_window(self):
        self.root.title("🔓 잠금 관리")
        self.root.configure(bg=Theme.BG)
        self.root.resizable(False, False)
        _center(self.root, 680, 540)

    def _build_ui(self):
        tk.Label(
            self.root, text="🔓 잠긴 폴더 관리",
            font=("맑은 고딕", 18, "bold"),
            bg=Theme.BG, fg=Theme.ACCENT,
        ).pack(pady=(20, 2))
        tk.Label(
            self.root, text="잠긴 폴더를 선택하여 해제하세요",
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(0, 14))

        # ── Treeview 목록 ─────────────────────────────────────
        list_frame = tk.Frame(self.root, bg=Theme.BG_LIGHT)
        list_frame.pack(fill="both", expand=False, padx=20, pady=(0, 10))

        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Custom.Treeview",
            background=Theme.BG_LIGHT, foreground=Theme.FG,
            fieldbackground=Theme.BG_LIGHT, rowheight=26, borderwidth=0,
        )
        style.configure(
            "Custom.Treeview.Heading",
            background=Theme.BG, foreground=Theme.FG, borderwidth=0,
        )
        style.map(
            "Custom.Treeview",
            background=[("selected", Theme.ACCENT)],
            foreground=[("selected", "#1e1e2e")],
        )

        cols = ("folder", "where", "when", "size")
        self.tree = ttk.Treeview(
            list_frame, columns=cols, show="headings",
            style="Custom.Treeview", height=11,
        )
        self.tree.heading("folder", text="폴더 이름")
        self.tree.heading("where",  text="원본 위치")
        self.tree.heading("when",   text="잠근 시점")
        self.tree.heading("size",   text="크기")
        self.tree.column("folder", width=170, anchor="w")
        self.tree.column("where",  width=260, anchor="w")
        self.tree.column("when",   width=130, anchor="w")
        self.tree.column("size",   width=70,  anchor="e")
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree.bind("<Double-1>", lambda e: self._on_unlock())

        # ── 진행률 / 상태 ─────────────────────────────────────
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=Theme.BG_LIGHT,
            background=Theme.ACCENT, thickness=6,
        )
        self.progress = ttk.Progressbar(
            self.root, style="Custom.Horizontal.TProgressbar",
            mode="determinate",
        )
        self.progress.pack(fill="x", padx=20, pady=(0, 4))

        self.status_var = tk.StringVar(value="준비됨")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(0, 8))

        # ── 상단 액션 버튼 ────────────────────────────────────
        top_btn = tk.Frame(self.root, bg=Theme.BG)
        top_btn.pack(pady=(2, 0))
        tk.Button(
            top_btn, text="🔓  선택 항목 해제",
            font=("맑은 고딕", 12, "bold"),
            bg=Theme.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=18, command=self._on_unlock,
        ).pack(side="left", padx=6, ipady=8)
        tk.Button(
            top_btn, text="🔄  새로고침",
            font=("맑은 고딕", 11),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=12, command=self._refresh,
        ).pack(side="left", padx=6, ipady=8)

        # ── 하단: 런처 / 비밀번호 수정 ────────────────────────
        bottom = tk.Frame(self.root, bg=Theme.BG)
        bottom.pack(side="bottom", pady=(0, 14))
        tk.Button(
            bottom, text="🔧  런처 다시 만들기",
            font=("맑은 고딕", 10),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=16, command=self._on_install_launcher,
        ).pack(side="left", padx=4, ipady=6)
        tk.Button(
            bottom, text="⚙  비밀번호 수정",
            font=("맑은 고딕", 10),
            bg=Theme.BG_LIGHT, fg=Theme.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=16, command=self._on_change_pw,
        ).pack(side="left", padx=4, ipady=6)

    # ── 헬퍼 ─────────────────────────────────────────────────
    def _refresh(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        items = self.vault.list_items()
        for it in items:
            when = it["locked_at"].replace("T", " ")[:16] if it["locked_at"] else ""
            self.tree.insert(
                "", "end",
                values=(it["folder_name"], it["original_parent"], when, _fmt_size(it["size"])),
                tags=(str(it["path"]),),
            )
        self.status_var.set(f"총 {len(items)}개 잠긴 항목")
        self.progress["value"] = 0

    def _update_progress(self, current: int, total: int):
        pct = int(current / total * 100) if total > 0 else 0
        self.progress["value"] = min(pct, 100)
        self.status_var.set(
            f"처리 중... {_fmt_size(current)} / {_fmt_size(total)} ({pct}%)"
        )
        self.root.update_idletasks()

    # ── 해제 ─────────────────────────────────────────────────
    def _on_unlock(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("경고", "해제할 항목을 선택해 주세요.", parent=self.root)
            return

        item = sel[0]
        locked_path = Path(self.tree.item(item, "tags")[0])
        if not locked_path.is_file():
            messagebox.showerror("오류", "선택한 항목을 찾을 수 없습니다.", parent=self.root)
            self._refresh()
            return

        # 1차 시도: 원본 위치에 복원
        try:
            self.progress["value"] = 0
            rp = CryptoEngine.unlock_folder(
                locked_path, self.password,
                progress_callback=self._update_progress,
            )
            self.progress["value"] = 100
            self.status_var.set("해제 완료!")
            messagebox.showinfo(
                "해제 완료",
                f"폴더가 복원되었습니다.\n\n  복원: {rp.name}/\n  위치: {rp.parent}",
                parent=self.root,
            )
            self._refresh()
            return

        except OriginalLocationMissingError as e:
            # 원본 위치 사라짐 → 사용자에게 위치 선택 요청
            ans = messagebox.askyesno(
                "원본 위치 없음",
                f"{e}\n\n복원할 위치를 직접 선택하시겠습니까?",
                parent=self.root,
            )
            if not ans:
                return
            chosen = filedialog.askdirectory(
                title="복원할 위치를 선택하세요", parent=self.root
            )
            if not chosen:
                return
            try:
                self.progress["value"] = 0
                rp = CryptoEngine.unlock_folder(
                    locked_path, self.password,
                    restore_parent_override=Path(chosen),
                    progress_callback=self._update_progress,
                )
                self.progress["value"] = 100
                self.status_var.set("해제 완료!")
                messagebox.showinfo(
                    "해제 완료",
                    f"폴더가 복원되었습니다.\n\n  복원: {rp.name}/\n  위치: {rp.parent}",
                    parent=self.root,
                )
                self._refresh()
            except Exception as ex:
                messagebox.showerror("오류", f"해제 중 오류 발생:\n{ex}", parent=self.root)

        except FolderExistsError as e:
            messagebox.showwarning("경고", str(e), parent=self.root)
        except WrongPasswordError:
            messagebox.showerror(
                "오류",
                "현재 마스터 비밀번호로 해당 파일을 풀 수 없습니다.\n"
                "(이전 비밀번호로 잠긴 파일일 수 있습니다)",
                parent=self.root,
            )
        except Exception as e:
            messagebox.showerror("오류", f"해제 중 오류 발생:\n{e}", parent=self.root)

    # ── 비밀번호 수정 ────────────────────────────────────────
    def _on_change_pw(self):
        dlg = tk.Toplevel(self.root)
        ChangePasswordDialog(dlg, self.password, on_done=self._on_pw_changed)

    def _on_pw_changed(self, new_password: str):
        self.password = new_password

    # ── 런처 다시 만들기 ─────────────────────────────────────
    def _on_install_launcher(self):
        install_launcher_ui(parent=self.root, ask=True)


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
            self.root, text="기존에 잠긴 모든 폴더가 새 비밀번호로 재암호화됩니다",
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
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

        style = ttk.Style()
        style.configure(
            "CP.Horizontal.TProgressbar",
            troughcolor=Theme.BG_LIGHT,
            background=Theme.ACCENT, thickness=6,
        )
        self.progress = ttk.Progressbar(
            self.root, style="CP.Horizontal.TProgressbar",
            mode="determinate",
        )
        self.progress.pack(fill="x", padx=40, pady=(0, 4))

        self.status_var = tk.StringVar(value="새 비밀번호를 입력하세요")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("맑은 고딕", 9), bg=Theme.BG, fg=Theme.DIM,
        ).pack(pady=(2, 12))

        btn_frame = tk.Frame(self.root, bg=Theme.BG)
        btn_frame.pack()
        self.save_btn = tk.Button(
            btn_frame, text="저장 및 재암호화",
            font=("맑은 고딕", 11, "bold"),
            bg=Theme.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=16, command=self._on_save,
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

        self.save_btn.config(state="disabled")
        self.cancel_btn.config(state="disabled")

        vault = VaultManager()
        items = vault.list_items()
        if not items:
            # 잠긴 항목이 없으면 검증값만 갱신
            try:
                MasterPasswordStore().set_password(pw1)
                messagebox.showinfo("완료", "비밀번호가 변경되었습니다.", parent=self.root)
                self.on_done(pw1)
                self.root.destroy()
            except Exception as e:
                messagebox.showerror("오류", f"오류 발생:\n{e}", parent=self.root)
                self.save_btn.config(state="normal")
                self.cancel_btn.config(state="normal")
            return

        # vault 재암호화 + 검증값 갱신
        self.progress["value"] = 0
        self.status_var.set(f"재암호화 중... 0/{len(items)}")
        self.root.update_idletasks()

        def progress_cb(done: int, total: int, name: str):
            pct = int(done / total * 100) if total > 0 else 100
            self.progress["value"] = pct
            self.status_var.set(f"재암호화 중... {done}/{total}")
            self.root.update_idletasks()

        try:
            vault.reencrypt_all(self.current_password, pw1, progress_callback=progress_cb)
            MasterPasswordStore().set_password(pw1)
            messagebox.showinfo(
                "완료",
                f"비밀번호가 변경되었으며 {len(items)}개 항목이 새 비밀번호로 재암호화되었습니다.",
                parent=self.root,
            )
            self.on_done(pw1)
            self.root.destroy()
        except Exception as e:
            messagebox.showerror(
                "오류",
                f"재암호화 중 오류 발생:\n{e}\n\n"
                "일부 파일은 새 비번으로, 일부는 이전 비번으로 남아 있을 수 있습니다.",
                parent=self.root,
            )
            self.save_btn.config(state="normal")
            self.cancel_btn.config(state="normal")


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

    successes = []
    failures = []
    for f in folders:
        f = Path(f).resolve()
        if not f.is_dir():
            failures.append((f, "폴더가 아닙니다"))
            continue
        try:
            CryptoEngine.lock_folder(f, password, VAULT_DIR)
            successes.append(f)
        except Exception as e:
            failures.append((f, str(e)))

    if successes and not failures:
        if len(successes) == 1:
            f = successes[0]
            messagebox.showinfo(
                "잠금 완료",
                f"'{f.name}' 폴더가 잠겼습니다.\n\n"
                "원본 폴더가 사라졌습니다.\n"
                "해제하려면 이 프로그램을 더블클릭하세요.",
                parent=parent,
            )
        else:
            names = "\n".join(f"  ▸ {f.name}" for f in successes)
            messagebox.showinfo(
                "잠금 완료",
                f"{len(successes)}개 폴더가 잠겼습니다:\n\n{names}",
                parent=parent,
            )
    elif failures and not successes:
        msgs = "\n".join(f"  ▸ {f.name}: {e}" for f, e in failures)
        messagebox.showerror("잠금 실패", f"잠금에 실패했습니다:\n\n{msgs}", parent=parent)
    else:
        s = "\n".join(f"  ✓ {f.name}" for f in successes)
        fl = "\n".join(f"  ✗ {p.name}: {e}" for p, e in failures)
        messagebox.showwarning(
            "부분 완료",
            f"성공:\n{s}\n\n실패:\n{fl}",
            parent=parent,
        )


# ════════════════════════════════════════════════════════════════
#  12. 외부 .locked 드래그 처리 (vault 밖에서 흘러나온 파일용)
# ════════════════════════════════════════════════════════════════

def unlock_external(password: str, locked_files: list, parent: Optional[tk.Tk] = None) -> None:
    """vault 밖의 .locked 파일들을 비번으로 해제 시도한다."""
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
#  13. 런처 설치 UI 헬퍼
# ════════════════════════════════════════════════════════════════

def install_launcher_ui(parent: Optional[tk.Misc] = None, ask: bool = True) -> Optional[Path]:
    """
    런처를 설치한다. ask=True면 먼저 yes/no 다이얼로그.
    설치 경로를 반환하거나, 취소/실패 시 None.
    """
    if sys.platform == "darwin":
        kind = ".app 번들"
    elif sys.platform == "win32":
        kind = ".bat 파일"
    else:
        kind = ".desktop 파일"

    location_label = LauncherInstaller.install_dir_label()

    if ask:
        ans = messagebox.askyesno(
            "런처 만들기",
            f"{location_label}에 드래그-앤-드롭 런처를 만드시겠습니까?\n\n"
            f"▸ FolderLock {kind} 생성\n"
            "▸ 폴더를 이 아이콘에 드래그하면 자동 잠금됩니다\n\n"
            "(나중에 메인 화면의 '런처 다시 만들기' 버튼으로\n"
            " 언제든 다시 만들 수 있습니다)",
            parent=parent,
        )
        if not ans:
            return None

    try:
        installer = LauncherInstaller()
        path = installer.install()
        messagebox.showinfo(
            "런처 생성 완료",
            f"런처가 생성되었습니다:\n\n"
            f"  위치: {path.parent}\n"
            f"  파일: {path.name}\n\n"
            "이제 폴더를 이 아이콘에 드래그하면 자동으로 잠깁니다.\n\n"
            "⚠ 참고: 런처는 현재 Python 경로와 folderLock.py 위치를\n"
            "기억합니다. 프로젝트 폴더나 가상환경을 이동했다면 런처를\n"
            "다시 만들어야 합니다.",
            parent=parent,
        )
        return path
    except PermissionError as e:
        messagebox.showerror(
            "런처 생성 실패 (권한)",
            f"런처를 만들 수 없습니다 — 권한이 거부되었습니다.\n\n{e}\n\n"
            "macOS에서 발생했다면 다음을 시도하세요:\n"
            "  ▸ Finder에서 기존 FolderLock.app을 휴지통으로 이동\n"
            "  ▸ 시스템 설정 → 개인정보 보호 및 보안 → 파일 및 폴더\n"
            "    에서 이 프로그램(또는 IDE)에 폴더 접근 권한 부여",
            parent=parent,
        )
        return None
    except Exception as e:
        messagebox.showerror(
            "런처 생성 실패",
            f"런처 생성 중 오류가 발생했습니다:\n{e}",
            parent=parent,
        )
        return None


# ════════════════════════════════════════════════════════════════
#  14. 메인 엔트리포인트
# ════════════════════════════════════════════════════════════════

def main():
    # ── CLI: --install-launcher (GUI 없이 바로 설치) ──────────
    if "--install-launcher" in sys.argv:
        try:
            path = LauncherInstaller().install()
            print(f"✓ 런처가 생성되었습니다: {path}")
        except Exception as e:
            print(f"✗ 런처 생성 실패: {e}")
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

    # ── (B) 인자 수집: sys.argv + (macOS) Apple Events ────────
    folders_from_args = []
    locked_from_args = []

    for a in sys.argv[1:]:
        p = Path(a).resolve()
        if p.is_dir():
            folders_from_args.append(p)
        elif p.is_file() and p.suffix == CryptoEngine.LOCKED_EXT:
            locked_from_args.append(p)

    mac_paths = []  # macOS Apple Events로 도착한 경로들

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

    def dispatch():
        folders = folders_from_args + [p for kind, p in mac_paths if kind == "folder"]
        lockeds = locked_from_args + [p for kind, p in mac_paths if kind == "locked"]

        if folders:
            lock_folders_silent(folders, parent=root)
            root.destroy()
        elif lockeds:
            handle_locked_external(lockeds)
        else:
            transition_to_gate(transition_to_main_app)

    # ── macOS: Apple Event 핸들러 등록 후 짧게 대기 ───────────
    if sys.platform == "darwin":
        def on_open_document(*args):
            for a in args:
                p = Path(a).resolve()
                if p.is_dir():
                    mac_paths.append(("folder", p))
                elif p.is_file() and p.suffix == CryptoEngine.LOCKED_EXT:
                    mac_paths.append(("locked", p))
        root.createcommand("::tk::mac::OpenDocument", on_open_document)
        # Apple Event는 비동기로 도착 — 800ms 정도 대기 후 분기
        root.after(800, dispatch)
    else:
        dispatch()

    root.mainloop()


if __name__ == "__main__":
    main()
