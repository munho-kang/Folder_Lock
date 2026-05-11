# 🔒 Folder Lock — Windows 설치 안내서

폴더를 통째로 암호화해서 하나의 잠금 파일로 만들어 주는 프로그램입니다.
마스터 비밀번호 1개로 모든 폴더를 잠그고, 잠긴 파일은 사용자 시야에서
보이지 않는 안전한 위치(vault)에 보관됩니다.

- 🔐 **AES-128-CBC + HMAC-SHA256** (Fernet) 청크 암호화
- 🔑 **PBKDF2-HMAC-SHA256** 480,000회 반복 키 유도
- 📦 **4 MB 청크 스트리밍** — 대용량 폴더 지원
- 🪟 **드래그-앤-드롭** — 바탕화면의 `FolderLock.bat`에 폴더만 끌어다 놓으면 잠금
- 🔄 **마스터 비밀번호 수정** 시 vault 내 모든 항목 자동 재암호화

---

## 📋 사전 준비

### 1. Python 설치

[python.org 공식 다운로드 페이지](https://www.python.org/downloads/windows/)에서
**Python 3.10 이상**을 받아 설치합니다.

> ⚠ 설치 화면에서 **"Add python.exe to PATH"** 체크박스를 반드시 켜 주세요.

설치 후 명령 프롬프트에서 확인:

```cmd
python --version
```

> 💡 Windows용 Python에는 `tkinter`가 기본 포함되어 있어 별도 설치가 필요 없습니다.

### 2. 프로젝트 파일 준비

`folderLock.py` 파일을 PC의 원하는 위치에 둡니다. 예시:

```
C:\Users\<사용자명>\Folder_Lock\folderLock.py
```

> 폴더 경로는 자유롭게 정하셔도 됩니다. 다만 한글이 들어간 경로보다는
> 영문 경로가 호환성에 더 안전합니다.

---

## ⚙️ 설치

명령 프롬프트(또는 PowerShell)를 열고 프로젝트 폴더로 이동합니다.

```cmd
cd C:\Users\<사용자명>\Folder_Lock
```

### 1. 가상환경(venv) 생성

```cmd
python -m venv .venv
```

### 2. `cryptography` 라이브러리 설치

```cmd
.venv\Scripts\pip install cryptography
```

---

## 🚀 첫 실행 — 마스터 비밀번호 설정

```cmd
.venv\Scripts\pythonw.exe folderLock.py
```

> `pythonw.exe`로 실행하면 콘솔 창 없이 GUI만 뜹니다.
> 디버깅하면서 콘솔 출력을 보고 싶다면 `python.exe`로 실행해도 됩니다.

다이얼로그가 뜨면:

1. **마스터 비밀번호 입력** (4자 이상) + 확인
2. "런처를 만드시겠습니까?" → **예** 클릭
3. 바탕화면에 `FolderLock.bat` 자동 생성

---

## 🎯 사용 방법

### 🔒 폴더 잠그기

방법 1: **드래그**
- 잠그고 싶은 폴더를 바탕화면의 `FolderLock.bat` 위로 드래그
- 자동으로 잠금 → 원본 폴더 삭제 → 잠금 완료 메시지

방법 2: **우클릭 → 보내기**
- 사전 설정 (1회): 탐색기 주소창에 `shell:sendto` 입력 → Enter →
  열린 폴더에 `FolderLock.bat`의 바로 가기를 복사
- 이후 폴더 우클릭 → **보내기** → **FolderLock**

### 🔓 폴더 풀기

1. `FolderLock.bat` 더블클릭
2. 마스터 비밀번호 입력
3. 잠긴 항목 목록에서 풀고 싶은 폴더 선택
4. **🔓 선택 항목 해제** 버튼 클릭 → 원본 위치에 복원

### ⚙ 마스터 비밀번호 변경

1. `FolderLock.bat` 더블클릭 → 비밀번호 입력
2. 메인 화면 하단의 **⚙ 비밀번호 수정** 클릭
3. 새 비밀번호 입력 → 저장
4. vault 내 모든 잠긴 폴더가 새 비밀번호로 자동 재암호화됨

---

## 📂 데이터 저장 위치

| 항목 | 경로 |
|---|---|
| 마스터 비밀번호 검증값 | `C:\Users\<사용자명>\.folderlock\config.json` |
| 잠긴 파일들 (vault) | `C:\Users\<사용자명>\.folderlock\vault\` |

`.folderlock` 폴더는 자동으로 hidden 속성이 부여되어 평소에는 보이지 않습니다.
탐색기에서 **보기 → 표시 → 숨김 항목**을 켜면 확인할 수 있습니다.

---

## 💡 편의 기능

### 작업 표시줄 / 시작 메뉴에 고정

`.bat` 파일은 직접 고정이 안 되므로 바로 가기를 통해 고정합니다:

1. `FolderLock.bat` 우클릭 → **바로 가기 만들기**
2. 생성된 `.lnk` 파일 우클릭 → **시작 화면에 고정** 또는 **작업 표시줄에 고정**

### 런처 다시 만들기

다음 상황에서는 런처를 다시 만들어야 합니다:

- 프로젝트 폴더를 다른 위치로 이동했을 때
- 가상환경(`.venv`)을 다시 만들었을 때
- Python을 업그레이드했을 때

방법 1: GUI
- `FolderLock.bat` 더블클릭 → 비밀번호 입력 → **🔧 런처 다시 만들기**

방법 2: CLI
```cmd
.venv\Scripts\python.exe folderLock.py --install-launcher
```

---

## ⚠️ 주의사항

- **마스터 비밀번호를 분실하면 잠긴 폴더를 영원히 복구할 수 없습니다.**
  반드시 안전한 곳에 보관하세요.
- 잠금 시 원본 폴더는 **삭제**됩니다. 중요한 데이터는 백업 후 사용하세요.
- 백신 프로그램이 `.bat` 파일을 의심할 수 있습니다. 안전한 동작이지만,
  예외 등록이 필요할 수 있습니다.
- `.folderlock` 폴더를 직접 수정하거나 삭제하면 잠긴 데이터를 잃을 수 있습니다.

---

## 🔧 문제 해결

### `cryptography 라이브러리가 설치되어 있지 않습니다` 오류

가상환경에 라이브러리가 제대로 설치되지 않았습니다. 다시 설치:

```cmd
.venv\Scripts\pip install --upgrade cryptography
```

### `ModuleNotFoundError: No module named '_tkinter'`

매우 드물지만 Python 설치에 tkinter가 포함되지 않은 경우입니다.
python.org 인스톨러로 **수정 설치(Modify)** → "tcl/tk and IDLE" 옵션을
체크해서 다시 설치하세요.

### 드래그해도 반응이 없음

런처(`FolderLock.bat`)가 가리키는 Python 경로나 스크립트 경로가
유효하지 않을 수 있습니다. 위의 "런처 다시 만들기"를 참고해 재생성하세요.

### "이 비밀번호로 풀 수 없습니다" 메시지

이전 마스터 비밀번호로 잠긴 파일일 수 있습니다. 비밀번호 변경 도중
중단된 경우 일부 파일이 옛 비번으로 남아 있을 수 있습니다.
이전 비밀번호를 안다면 비밀번호 변경을 다시 시도하세요.

---

## 🛠 명령어 빠른 참조

| 작업 | 명령어 |
|---|---|
| 가상환경 생성 | `python -m venv .venv` |
| 의존성 설치 | `.venv\Scripts\pip install cryptography` |
| GUI 실행 (콘솔 없음) | `.venv\Scripts\pythonw.exe folderLock.py` |
| GUI 실행 (디버그) | `.venv\Scripts\python.exe folderLock.py` |
| 런처 재생성 | `.venv\Scripts\python.exe folderLock.py --install-launcher` |
| 폴더 잠금 (CLI) | `.venv\Scripts\python.exe folderLock.py "C:\path\to\folder"` |

---

## 🔐 보안 메모

- 비밀번호 검증값과 vault는 `~/.folderlock/`에 저장됩니다.
- 마스터 비밀번호는 **기계 종속 키**로 obfuscate된 채 `config.json`에 저장되어,
  드래그-앤-드롭 시 비밀번호 입력 없이 잠금이 가능합니다.
- 다른 PC/사용자로 `config.json`을 옮기면 마스터 비밀번호 복호화가 불가능합니다.
- 각 `.locked` 파일은 자체 salt + PBKDF2 + Fernet 키로 독립 암호화됩니다.
