#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════╗
║        🔒  폴더 통째로 잠금(암호화) 프로그램  🔒         ║
║                                                          ║
║  잠금 : 폴더 → tar 아카이브 → Fernet 암호화             ║
║         → 단일 .locked 파일 생성 → 원본 폴더 삭제       ║
║                                                          ║
║  해제 : .locked 파일 → Fernet 복호화 → tar 추출         ║
║         → 원본 폴더 복원 → .locked 파일 삭제            ║
║                                                          ║
║  ▸ PBKDF2-HMAC-SHA256 기반 키 유도                      ║
║  ▸ Fernet (AES-128-CBC + HMAC-SHA256) 암호화            ║
║  ▸ 4MB 청크 단위 스트리밍 처리 (대용량 지원)            ║
║  ▸ tkinter GUI                                           ║
╚══════════════════════════════════════════════════════════╝

사전 준비:
    pip install cryptography

실행 방법:
    python folder_lock.py
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
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from typing import Optional

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
#  1. 사용자 정의 예외 클래스
# ════════════════════════════════════════════════════════════════

class AlreadyLockedError(Exception):
    """이미 .locked 파일이 존재할 때 발생"""
    pass


class NotLockedFileError(Exception):
    """.locked 파일이 아닌 것을 해제하려 할 때 발생"""
    pass


class WrongPasswordError(Exception):
    """비밀번호가 틀렸을 때 발생"""
    pass


class FolderExistsError(Exception):
    """복원 대상 폴더가 이미 존재할 때 발생"""
    pass


# ════════════════════════════════════════════════════════════════
#  2. 암호화 엔진 클래스 — 폴더 통째 암호화/복호화
# ════════════════════════════════════════════════════════════════

class CryptoEngine:
    """
    폴더 전체를 하나의 암호화된 .locked 파일로 변환하는 엔진.

    ── 잠금 흐름 ──────────────────────────────────────────
    원본 폴더
      → tar 아카이브 (파일명·구조·권한 모두 보존)
      → Fernet 청크 암호화
      → [헤더(메타데이터)] + [암호화 청크들] = 단일 .locked 파일
      → 원본 폴더 삭제

    ── 해제 흐름 ──────────────────────────────────────────
    .locked 파일
      → 헤더에서 salt 추출 & 비밀번호 검증
      → Fernet 청크 복호화
      → tar 추출 → 원본 폴더 복원
      → .locked 파일 삭제
    """

    # ── 상수 ─────────────────────────────────────────────────
    LOCKED_EXT     = ".locked"        # 잠금 파일 확장자
    KDF_ITERATIONS = 480_000          # PBKDF2 반복 횟수
    CHUNK_SIZE     = 4 * 1024 * 1024  # 4 MB 청크
    HEADER_MAGIC   = b"FLOCK01\x00"   # 파일 포맷 식별 매직 바이트 (8바이트)

    # ── 키 유도 ──────────────────────────────────────────────
    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """
        비밀번호(str) + salt(bytes) → Fernet 키(URL-safe base64 bytes).

        PBKDF2-HMAC-SHA256을 48만 회 반복하여
        브루트포스 공격을 실질적으로 불가능하게 만든다.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=CryptoEngine.KDF_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    # ── 비밀번호 검증용 해시 ─────────────────────────────────
    @staticmethod
    def _make_pw_check(password: str, salt: bytes) -> str:
        """
        SHA-256(password + salt)의 hex digest.
        복호화 전 비밀번호가 맞는지 빠르게 확인하는 용도.
        (이 해시로 원본 비밀번호를 복원할 수 없다.)
        """
        return hashlib.sha256(password.encode("utf-8") + salt).hexdigest()

    # ── 헤더 생성 ────────────────────────────────────────────
    @classmethod
    def _build_header(cls, password: str, salt: bytes, folder_name: str) -> bytes:
        """
        .locked 파일의 헤더를 구성한다.

        구조:
          [8B 매직] [4B 헤더JSON길이] [가변 헤더JSON]

        헤더 JSON 내용:
          - salt            : 키 유도에 사용된 salt (base64)
          - pw_check        : 비밀번호 검증 해시 (hex)
          - folder_name     : 복원할 폴더 이름
          - iterations      : PBKDF2 반복 횟수
          - version         : 포맷 버전
        """
        meta = {
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "pw_check": cls._make_pw_check(password, salt),
            "folder_name": folder_name,
            "iterations": cls.KDF_ITERATIONS,
            "version": 1,
        }
        meta_bytes = json.dumps(meta, ensure_ascii=False).encode("utf-8")
        return cls.HEADER_MAGIC + len(meta_bytes).to_bytes(4, "big") + meta_bytes

    # ── 헤더 파싱 ────────────────────────────────────────────
    @classmethod
    def _parse_header(cls, f) -> dict:
        """
        파일 핸들에서 헤더를 읽어 dict로 반환한다.
        매직 바이트가 일치하지 않으면 ValueError를 발생시킨다.
        """
        magic = f.read(8)
        if magic != cls.HEADER_MAGIC:
            raise ValueError("올바른 .locked 파일이 아닙니다.")

        meta_len = int.from_bytes(f.read(4), "big")
        meta_bytes = f.read(meta_len)
        return json.loads(meta_bytes.decode("utf-8"))

    # ═══════════════════════════════════════════════════════════
    #  핵심 공개 메서드: 잠금 / 해제
    # ═══════════════════════════════════════════════════════════

    @classmethod
    def lock_folder(
        cls,
        folder: Path,
        password: str,
        progress_callback=None,
    ) -> Path:
        """
        폴더 전체를 암호화하여 단일 .locked 파일로 만든다.

        처리 순서:
          1) 폴더를 tar 아카이브로 압축 (임시 파일)
          2) salt 생성 → PBKDF2 → Fernet 키 유도
          3) 헤더 기록 → tar를 청크 단위로 Fernet 암호화하여 기록
          4) 원본 폴더 삭제
          5) 임시 파일 정리

        반환값: 생성된 .locked 파일의 Path
        """
        folder = Path(folder).resolve()

        # ── 사전 검증 ────────────────────────────────────────
        if not folder.is_dir():
            raise FileNotFoundError(f"폴더를 찾을 수 없습니다: {folder}")

        locked_path = folder.with_name(folder.name + cls.LOCKED_EXT)
        if locked_path.exists():
            raise AlreadyLockedError(
                f"이미 '{locked_path.name}' 파일이 존재합니다.\n"
                "기존 잠금 파일을 삭제하거나 이름을 변경한 후 다시 시도하세요."
            )

        # ── 1단계: tar 아카이브 생성 ─────────────────────────
        tmp_tar_fd, tmp_tar_path = tempfile.mkstemp(suffix=".tar")
        os.close(tmp_tar_fd)
        try:
            with tarfile.open(tmp_tar_path, "w") as tar:
                # arcname="." → 추출 시 폴더 내용물만 복원
                tar.add(str(folder), arcname=".")

            tar_size = os.path.getsize(tmp_tar_path)

            # ── 2단계: salt 생성 & 키 유도 ───────────────────
            salt = secrets.token_bytes(16)
            key = cls._derive_key(password, salt)
            fernet = Fernet(key)

            # ── 3단계: 헤더 + 암호화 청크 기록 ───────────────
            header = cls._build_header(password, salt, folder.name)
            bytes_done = 0

            with open(tmp_tar_path, "rb") as fin, \
                 open(locked_path, "wb") as fout:

                fout.write(header)

                while True:
                    chunk = fin.read(cls.CHUNK_SIZE)
                    if not chunk:
                        break
                    encrypted = fernet.encrypt(chunk)
                    # [8바이트 청크 길이] + [암호화 데이터]
                    fout.write(len(encrypted).to_bytes(8, "big"))
                    fout.write(encrypted)

                    bytes_done += len(chunk)
                    if progress_callback:
                        progress_callback(bytes_done, tar_size)

            # ── 4단계: 원본 폴더 삭제 ────────────────────────
            shutil.rmtree(folder)

        finally:
            # ── 5단계: 임시 tar 파일 정리 ────────────────────
            if os.path.exists(tmp_tar_path):
                os.unlink(tmp_tar_path)

        return locked_path

    @classmethod
    def unlock_folder(
        cls,
        locked_file: Path,
        password: str,
        progress_callback=None,
    ) -> Path:
        """
        .locked 파일을 복호화하여 원본 폴더를 복원한다.

        처리 순서:
          1) 헤더 파싱 → salt 추출
          2) 비밀번호 검증
          3) Fernet 키 유도 → 청크 복호화 → 임시 tar 파일 생성
          4) tar 추출 → 원본 폴더 복원
          5) .locked 파일 삭제
          6) 임시 파일 정리

        반환값: 복원된 폴더의 Path
        """
        locked_file = Path(locked_file).resolve()

        if not locked_file.is_file():
            raise FileNotFoundError(f"파일을 찾을 수 없습니다: {locked_file}")
        if not locked_file.name.endswith(cls.LOCKED_EXT):
            raise NotLockedFileError("선택한 파일이 .locked 파일이 아닙니다.")

        file_size = locked_file.stat().st_size

        tmp_tar_fd, tmp_tar_path = tempfile.mkstemp(suffix=".tar")
        os.close(tmp_tar_fd)

        try:
            with open(locked_file, "rb") as fin:
                # ── 1단계: 헤더 파싱 ─────────────────────────
                meta = cls._parse_header(fin)
                salt = base64.urlsafe_b64decode(meta["salt"])
                folder_name = meta["folder_name"]

                # ── 2단계: 비밀번호 검증 ─────────────────────
                if cls._make_pw_check(password, salt) != meta["pw_check"]:
                    raise WrongPasswordError("비밀번호가 일치하지 않습니다.")

                # ── 3단계: 복호화 → 임시 tar ─────────────────
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

            # ── 4단계: tar 추출 → 폴더 복원 ──────────────────
            restore_path = locked_file.parent / folder_name
            if restore_path.exists():
                raise FolderExistsError(
                    f"'{folder_name}' 폴더가 이미 존재합니다.\n"
                    "기존 폴더를 이동하거나 이름을 변경한 후 다시 시도하세요."
                )

            restore_path.mkdir(parents=True)
            with tarfile.open(tmp_tar_path, "r") as tar:
                # 안전한 추출: 경로 탈출(path traversal) 방지
                for member in tar.getmembers():
                    member_path = (restore_path / member.name).resolve()
                    if not str(member_path).startswith(str(restore_path.resolve())):
                        raise ValueError(f"위험한 경로가 감지되었습니다: {member.name}")
                tar.extractall(path=str(restore_path))

            # ── 5단계: .locked 파일 삭제 ──────────────────────
            locked_file.unlink()

        finally:
            # ── 6단계: 임시 tar 파일 정리 ─────────────────────
            if os.path.exists(tmp_tar_path):
                os.unlink(tmp_tar_path)

        return restore_path


# ════════════════════════════════════════════════════════════════
#  3-A. 더블클릭 해제 다이얼로그 — .locked 파일을 직접 열었을 때
# ════════════════════════════════════════════════════════════════

class UnlockDialog:
    """
    .locked 파일을 더블클릭(또는 CLI 인자)으로 열었을 때 표시되는
    간략한 비밀번호 입력 → 해제 전용 다이얼로그.
    """

    BG           = "#1e1e2e"
    BG_LIGHT     = "#2a2a3c"
    FG           = "#cdd6f4"
    ACCENT       = "#89b4fa"
    UNLOCK_COLOR = "#a6e3a1"
    DIM          = "#6c7086"

    def __init__(self, root: tk.Tk, locked_file: Path):
        self.root = root
        self.locked_file = locked_file
        self._setup_window()
        self._build_ui()

    def _setup_window(self):
        self.root.title("🔓 잠금 해제")
        self.root.configure(bg=self.BG)
        self.root.resizable(False, False)
        w, h = 420, 250
        sx = (self.root.winfo_screenwidth() - w) // 2
        sy = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{sx}+{sy}")
        self.root.bind("<Return>", lambda e: self._on_unlock())
        self.root.bind("<Escape>", lambda e: self.root.destroy())

    def _build_ui(self):
        tk.Label(
            self.root, text="🔓 잠금 해제",
            font=("맑은 고딕", 16, "bold"),
            bg=self.BG, fg=self.ACCENT,
        ).pack(pady=(22, 4))

        tk.Label(
            self.root, text=self.locked_file.name,
            font=("맑은 고딕", 9), bg=self.BG, fg=self.DIM,
        ).pack(pady=(0, 14))

        pw_row = tk.Frame(self.root, bg=self.BG)
        pw_row.pack(fill="x", padx=30)

        self.pw_var = tk.StringVar()
        self._show_pw = False
        self.pw_entry = tk.Entry(
            pw_row, textvariable=self.pw_var,
            font=("맑은 고딕", 12), show="●",
            bg=self.BG_LIGHT, fg=self.FG,
            insertbackground=self.FG, relief="flat",
        )
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=7)

        tk.Button(
            pw_row, text="👁", font=("맑은 고딕", 11),
            bg=self.BG_LIGHT, fg=self.FG,
            relief="flat", cursor="hand2", width=3,
            command=self._toggle_pw,
        ).pack(side="right", padx=(4, 0), ipady=5)

        self.pw_entry.focus_set()

        btn_frame = tk.Frame(self.root, bg=self.BG)
        btn_frame.pack(pady=(18, 0))

        tk.Button(
            btn_frame, text="🔓  해제",
            font=("맑은 고딕", 12, "bold"),
            bg=self.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=12, command=self._on_unlock,
        ).pack(side="left", padx=8, ipady=6)

        tk.Button(
            btn_frame, text="취소",
            font=("맑은 고딕", 12),
            bg=self.BG_LIGHT, fg=self.FG,
            activebackground="#3a3a4c", relief="flat",
            cursor="hand2", width=8, command=self.root.destroy,
        ).pack(side="left", padx=8, ipady=6)

        self.status_var = tk.StringVar(value="비밀번호를 입력하세요")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("맑은 고딕", 9), bg=self.BG, fg=self.DIM,
        ).pack(pady=(10, 0))

    def _toggle_pw(self):
        self._show_pw = not self._show_pw
        self.pw_entry.config(show="" if self._show_pw else "●")

    def _on_unlock(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("경고", "비밀번호를 입력해 주세요.", parent=self.root)
            return

        self.status_var.set("복호화 중...")
        self.root.update_idletasks()

        try:
            rp = CryptoEngine.unlock_folder(self.locked_file, pw)
            messagebox.showinfo(
                "해제 완료",
                f"폴더가 성공적으로 복원되었습니다.\n\n"
                f"  복원: {rp.name}/\n"
                f"  위치: {rp.parent}",
                parent=self.root,
            )
            self.root.destroy()
        except WrongPasswordError:
            self.pw_var.set("")
            self.status_var.set("비밀번호가 틀렸습니다. 다시 입력하세요.")
            self.pw_entry.focus_set()
        except FolderExistsError as e:
            messagebox.showwarning("경고", str(e), parent=self.root)
        except ValueError as e:
            messagebox.showerror("파일 오류", str(e), parent=self.root)
        except Exception as e:
            messagebox.showerror("오류", f"해제 중 오류 발생:\n{e}", parent=self.root)
        finally:
            self.pw_var.set("")


# ════════════════════════════════════════════════════════════════
#  3-B. GUI 클래스 — tkinter 기반 사용자 인터페이스
# ════════════════════════════════════════════════════════════════

class FolderLockApp:
    """
    tkinter 기반 폴더 잠금/해제 GUI.

    [잠금] 폴더 선택 → 비밀번호 입력 → 폴더가 사라지고 .locked 파일 생성
    [해제] .locked 파일 선택 → 비밀번호 입력 → 원본 폴더 복원
    """

    # ── 색상 테마 (Catppuccin Mocha 기반) ────────────────────
    BG           = "#1e1e2e"
    BG_LIGHT     = "#2a2a3c"
    FG           = "#cdd6f4"
    ACCENT       = "#89b4fa"
    LOCK_COLOR   = "#f38ba8"
    UNLOCK_COLOR = "#a6e3a1"
    DIM          = "#6c7086"

    def __init__(self, root: tk.Tk):
        self.root = root
        self._setup_window()
        self._build_ui()

    # ── 윈도우 설정 ──────────────────────────────────────────
    def _setup_window(self):
        self.root.title("🔒 폴더 잠금 프로그램")
        self.root.configure(bg=self.BG)
        self.root.resizable(False, False)
        w, h = 560, 500
        sx = (self.root.winfo_screenwidth() - w) // 2
        sy = (self.root.winfo_screenheight() - h) // 2
        self.root.geometry(f"{w}x{h}+{sx}+{sy}")

    # ── UI 구성 ──────────────────────────────────────────────
    def _build_ui(self):

        # ── 타이틀 ───────────────────────────────────────────
        tk.Label(
            self.root, text="🔒 폴더 잠금 프로그램",
            font=("맑은 고딕", 18, "bold"),
            bg=self.BG, fg=self.ACCENT,
        ).pack(pady=(20, 2))

        tk.Label(
            self.root,
            text="폴더를 통째로 암호화하여 하나의 잠금 파일로 만듭니다",
            font=("맑은 고딕", 9), bg=self.BG, fg=self.DIM,
        ).pack(pady=(0, 18))

        # ── 잠금 대상: 폴더 선택 ─────────────────────────────
        self._make_section("잠금할 폴더 선택")
        row1 = tk.Frame(self.root, bg=self.BG)
        row1.pack(fill="x", padx=30, pady=(4, 0))

        self.folder_var = tk.StringVar(value="폴더를 선택하세요...")
        tk.Entry(
            row1, textvariable=self.folder_var,
            font=("맑은 고딕", 9), bg=self.BG_LIGHT, fg=self.FG,
            insertbackground=self.FG, relief="flat",
            state="readonly", readonlybackground=self.BG_LIGHT,
        ).pack(side="left", fill="x", expand=True, ipady=6)
        tk.Button(
            row1, text="폴더 선택", font=("맑은 고딕", 9),
            bg=self.ACCENT, fg="#1e1e2e", activebackground="#b4d0fb",
            relief="flat", cursor="hand2", command=self._browse_folder,
        ).pack(side="right", padx=(8, 0), ipady=3, ipadx=8)

        # ── 해제 대상: .locked 파일 선택 ─────────────────────
        self._make_section("해제할 .locked 파일 선택")
        row2 = tk.Frame(self.root, bg=self.BG)
        row2.pack(fill="x", padx=30, pady=(4, 0))

        self.file_var = tk.StringVar(value=".locked 파일을 선택하세요...")
        tk.Entry(
            row2, textvariable=self.file_var,
            font=("맑은 고딕", 9), bg=self.BG_LIGHT, fg=self.FG,
            insertbackground=self.FG, relief="flat",
            state="readonly", readonlybackground=self.BG_LIGHT,
        ).pack(side="left", fill="x", expand=True, ipady=6)
        tk.Button(
            row2, text="파일 선택", font=("맑은 고딕", 9),
            bg=self.ACCENT, fg="#1e1e2e", activebackground="#b4d0fb",
            relief="flat", cursor="hand2", command=self._browse_file,
        ).pack(side="right", padx=(8, 0), ipady=3, ipadx=8)

        # ── 비밀번호 ─────────────────────────────────────────
        self._make_section("비밀번호")
        pw_row = tk.Frame(self.root, bg=self.BG)
        pw_row.pack(fill="x", padx=30, pady=(4, 0))

        self.pw_var = tk.StringVar()
        self.pw_entry = tk.Entry(
            pw_row, textvariable=self.pw_var,
            font=("맑은 고딕", 11), show="●",
            bg=self.BG_LIGHT, fg=self.FG,
            insertbackground=self.FG, relief="flat",
        )
        self.pw_entry.pack(side="left", fill="x", expand=True, ipady=6)

        self._show_pw = False
        self.toggle_btn = tk.Button(
            pw_row, text="👁", font=("맑은 고딕", 11),
            bg=self.BG_LIGHT, fg=self.FG,
            relief="flat", cursor="hand2", width=3,
            command=self._toggle_pw,
        )
        self.toggle_btn.pack(side="right", padx=(4, 0), ipady=3)

        # ── 잠금 / 해제 버튼 ─────────────────────────────────
        btn_frame = tk.Frame(self.root, bg=self.BG)
        btn_frame.pack(pady=(25, 0))

        tk.Button(
            btn_frame, text="🔒  폴더 잠금",
            font=("맑은 고딕", 12, "bold"),
            bg=self.LOCK_COLOR, fg="#1e1e2e",
            activebackground="#f5a0b8", relief="flat",
            cursor="hand2", width=15, command=self._on_lock,
        ).pack(side="left", padx=10, ipady=8)

        tk.Button(
            btn_frame, text="🔓  잠금 해제",
            font=("맑은 고딕", 12, "bold"),
            bg=self.UNLOCK_COLOR, fg="#1e1e2e",
            activebackground="#bfeab7", relief="flat",
            cursor="hand2", width=15, command=self._on_unlock,
        ).pack(side="left", padx=10, ipady=8)

        # ── 프로그레스바 ─────────────────────────────────────
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=self.BG_LIGHT,
            background=self.ACCENT, thickness=8,
        )
        self.progress = ttk.Progressbar(
            self.root, style="Custom.Horizontal.TProgressbar",
            mode="determinate",
        )
        self.progress.pack(fill="x", padx=30, pady=(20, 0))

        # ── 상태 표시줄 ──────────────────────────────────────
        self.status_var = tk.StringVar(value="준비됨")
        tk.Label(
            self.root, textvariable=self.status_var,
            font=("맑은 고딕", 9), bg=self.BG, fg=self.DIM,
        ).pack(pady=(6, 10))

    # ── 헬퍼 ─────────────────────────────────────────────────
    def _make_section(self, text: str):
        tk.Label(
            self.root, text=text,
            font=("맑은 고딕", 10, "bold"),
            bg=self.BG, fg=self.FG,
        ).pack(anchor="w", padx=30, pady=(12, 0))

    def _browse_folder(self):
        p = filedialog.askdirectory(title="잠금할 폴더를 선택하세요")
        if p:
            self.folder_var.set(p)
            self.status_var.set(f"폴더 선택됨: {Path(p).name}")

    def _browse_file(self):
        p = filedialog.askopenfilename(
            title="해제할 .locked 파일을 선택하세요",
            filetypes=[("잠금 파일", "*.locked"), ("모든 파일", "*.*")],
        )
        if p:
            self.file_var.set(p)
            self.status_var.set(f"파일 선택됨: {Path(p).name}")

    def _toggle_pw(self):
        self._show_pw = not self._show_pw
        self.pw_entry.config(show="" if self._show_pw else "●")
        self.toggle_btn.config(text="🙈" if self._show_pw else "👁")

    def _check_pw(self) -> bool:
        pw = self.pw_var.get().strip()
        if not pw:
            messagebox.showwarning("경고", "비밀번호를 입력해 주세요.")
            return False
        if len(pw) < 4:
            messagebox.showwarning("경고", "비밀번호는 최소 4자 이상이어야 합니다.")
            return False
        return True

    @staticmethod
    def _fmt_size(b: int) -> str:
        """바이트를 읽기 좋은 단위로 변환"""
        if b < 1024: return f"{b} B"
        if b < 1024**2: return f"{b/1024:.1f} KB"
        if b < 1024**3: return f"{b/1024**2:.1f} MB"
        return f"{b/1024**3:.2f} GB"

    def _update_progress(self, current: int, total: int):
        pct = int(current / total * 100) if total > 0 else 0
        self.progress["value"] = min(pct, 100)
        self.status_var.set(
            f"처리 중... {self._fmt_size(current)} / {self._fmt_size(total)} ({pct}%)"
        )
        self.root.update_idletasks()

    # ── 잠금 실행 ────────────────────────────────────────────
    def _on_lock(self):
        fv = self.folder_var.get()
        if fv == "폴더를 선택하세요..." or not Path(fv).is_dir():
            messagebox.showwarning("경고", "먼저 잠금할 폴더를 선택해 주세요.")
            return
        if not self._check_pw():
            return

        folder = Path(fv)
        fc = sum(1 for _ in folder.rglob("*") if _.is_file())
        if fc == 0:
            messagebox.showwarning("경고", "폴더가 비어 있습니다.")
            return

        if not messagebox.askyesno(
            "확인",
            f"'{folder.name}' 폴더를 잠그시겠습니까?\n\n"
            f"  포함된 파일: {fc}개\n\n"
            f"▸ 폴더가 사라지고 '{folder.name}.locked' 파일이 생성됩니다.\n"
            f"▸ 비밀번호를 분실하면 복구할 수 없습니다!",
        ):
            return

        try:
            self.progress["value"] = 0
            lp = CryptoEngine.lock_folder(
                folder, self.pw_var.get(), self._update_progress,
            )
            self.progress["value"] = 100
            self.folder_var.set("폴더를 선택하세요...")
            self.status_var.set("잠금 완료!")
            messagebox.showinfo(
                "잠금 완료",
                f"폴더가 성공적으로 잠겼습니다.\n\n"
                f"  생성: {lp.name}\n"
                f"  크기: {self._fmt_size(lp.stat().st_size)}\n"
                f"  위치: {lp.parent}",
            )
        except AlreadyLockedError as e:
            messagebox.showwarning("경고", str(e))
        except Exception as e:
            messagebox.showerror("오류", f"잠금 중 오류 발생:\n{e}")
        finally:
            self.pw_var.set("")

    # ── 해제 실행 ────────────────────────────────────────────
    def _on_unlock(self):
        fv = self.file_var.get()
        if fv == ".locked 파일을 선택하세요..." or not Path(fv).is_file():
            messagebox.showwarning("경고", "먼저 해제할 .locked 파일을 선택해 주세요.")
            return
        if not self._check_pw():
            return

        try:
            self.progress["value"] = 0
            rp = CryptoEngine.unlock_folder(
                Path(fv), self.pw_var.get(), self._update_progress,
            )
            self.progress["value"] = 100
            self.file_var.set(".locked 파일을 선택하세요...")
            self.status_var.set("잠금 해제 완료!")
            messagebox.showinfo(
                "해제 완료",
                f"폴더가 성공적으로 복원되었습니다.\n\n"
                f"  복원: {rp.name}/\n"
                f"  위치: {rp.parent}",
            )
        except WrongPasswordError as e:
            messagebox.showerror("비밀번호 오류", str(e))
        except NotLockedFileError as e:
            messagebox.showwarning("경고", str(e))
        except FolderExistsError as e:
            messagebox.showwarning("경고", str(e))
        except ValueError as e:
            messagebox.showerror("파일 오류", str(e))
        except Exception as e:
            messagebox.showerror("오류", f"해제 중 오류 발생:\n{e}")
        finally:
            self.pw_var.set("")


# ════════════════════════════════════════════════════════════════
#  4. 메인 엔트리포인트
# ════════════════════════════════════════════════════════════════

def main():
    root = tk.Tk()
    root.withdraw()

    _started = [False]

    def _show_unlock(path: Path):
        if _started[0]:
            return
        _started[0] = True
        root.deiconify()
        UnlockDialog(root, path)

    def _show_main():
        if _started[0]:
            return
        _started[0] = True
        root.deiconify()
        FolderLockApp(root)

    # ── macOS: Finder 더블클릭 → Apple Events로 파일 전달 ─────
    if sys.platform == "darwin":
        def _open_document(*args):
            if args:
                locked_file = Path(args[0]).resolve()
                if locked_file.suffix == ".locked" and locked_file.is_file():
                    _show_unlock(locked_file)
                    return
            _show_main()
        root.createcommand("::tk::mac::OpenDocument", _open_document)

    # ── sys.argv: 터미널 실행 또는 Windows 더블클릭 ───────────
    if len(sys.argv) > 1:
        locked_file = Path(sys.argv[1]).resolve()
        if locked_file.suffix == ".locked" and locked_file.is_file():
            _show_unlock(locked_file)
        else:
            _show_main()
    elif sys.platform == "darwin":
        # macOS: Apple Event 도착 대기 후 없으면 메인 GUI 표시
        root.after(2000, _show_main)
    else:
        # Windows/Linux: sys.argv로만 파일을 받으므로 바로 메인 GUI
        _show_main()

    root.mainloop()


if __name__ == "__main__":
    main()