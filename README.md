# 🔒 Folder Lock — Windows 설치 안내서

폴더를 통째로 암호화해서 같은 자리에 `.locked` 파일로 만들어 주는 프로그램입니다.
마스터 비밀번호 1개로 모든 폴더를 잠그고, 잠긴 폴더는 원래 위치에 그대로 보이며
**더블클릭으로 바로 해제**할 수 있습니다.

- 🔐 **AES-128-CBC + HMAC-SHA256** (Fernet) 청크 암호화
- 🔑 **PBKDF2-HMAC-SHA256** 480,000회 반복 키 유도
- 📦 **4 MB 청크 스트리밍** — 대용량 폴더 지원
- 🖱 **탐색기 우클릭** — 폴더 우클릭 → "🔒 폴더 잠금" 한 번이면 끝
- 🔓 **더블클릭 해제** — `.locked` 파일을 더블클릭 → 비번 입력 → 원래 폴더 복원

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

## 🚀 첫 실행 — 마스터 비밀번호 설정 + 탐색기 통합

```cmd
.venv\Scripts\pythonw.exe folderLock.py
```

> `pythonw.exe`로 실행하면 콘솔 창 없이 GUI만 뜹니다.
> 디버깅하면서 콘솔 출력을 보고 싶다면 `python.exe`로 실행해도 됩니다.

다이얼로그가 뜨면:

1. **마스터 비밀번호 입력** (4자 이상) + 확인
2. "탐색기에 우클릭 메뉴 / 파일 연결을 등록할까요?" → **예** 클릭
3. 레지스트리에 두 가지가 등록됨:
   - 폴더 우클릭 → **"🔒 폴더 잠금"**
   - `.locked` 파일 더블클릭 → 자동 해제

---

## 🎯 사용 방법

### 🔒 폴더 잠그기

탐색기에서 잠그고 싶은 **폴더를 우클릭** → **🔒 폴더 잠금** 클릭

자동으로:
1. 폴더가 암호화됨
2. 같은 위치에 `폴더이름.locked` 파일이 생김
3. 원본 폴더는 삭제됨

> 💡 같은 이름의 `.locked` 파일이 이미 있으면 잠금이 거부됩니다.
> 기존 파일을 이동/이름변경한 후 다시 시도하세요.

### 🔓 폴더 풀기

`폴더이름.locked` 파일을 **더블클릭** → 비밀번호 입력 → 즉시 원래 폴더로 복원

> 💡 `.locked` 파일을 다른 위치로 옮긴 뒤 더블클릭해도 됩니다.
> 원본 위치(헤더에 기록됨)가 사라졌으면 복원 위치를 직접 선택할 수 있습니다.

### 🪟 메인 화면에서 직접 잠금/해제

레지스트리 등록 없이 GUI로만 쓰고 싶다면, `pythonw folderLock.py` 실행 후
비번 입력 → 홈 화면에서:

- 🔒 **폴더 선택해서 잠그기** — 파일 다이얼로그로 폴더 선택
- 🔓 **.locked 파일 선택해서 풀기** — 파일 다이얼로그로 `.locked` 선택

### ⚙ 마스터 비밀번호 변경

1. `pythonw folderLock.py` 실행 → 비밀번호 입력
2. 메인 화면 하단의 **⚙ 비밀번호 수정** 클릭
3. 새 비밀번호 입력 → 저장

> ⚠ **기존에 잠긴 `.locked` 파일들은 새 비밀번호로 자동 변환되지 않습니다.**
> 기존 파일을 해제하려면 이전 비밀번호가 필요합니다.
> 가능하면 모든 `.locked` 파일을 먼저 해제한 뒤 비밀번호를 변경하세요.

---

## 📂 데이터 저장 위치

| 항목 | 경로 |
|---|---|
| 마스터 비밀번호 검증값 | `C:\Users\<사용자명>\.folderlock\config.json` |
| 잠긴 폴더 (`.locked` 파일) | **원래 폴더가 있던 위치** |

`.folderlock` 폴더는 자동으로 hidden 속성이 부여되어 평소에는 보이지 않습니다.
탐색기에서 **보기 → 표시 → 숨김 항목**을 켜면 확인할 수 있습니다.

---

## 💡 편의 기능

### 탐색기 통합 다시 등록하기

다음 상황에서는 우클릭 메뉴 / 파일 연결을 다시 등록해야 합니다:

- 프로젝트 폴더를 다른 위치로 이동했을 때
- 가상환경(`.venv`)을 다시 만들었을 때
- Python을 업그레이드했을 때

방법 1: GUI
- `pythonw folderLock.py` → 비밀번호 입력 → **🔧 우클릭 메뉴 등록**

방법 2: CLI
```cmd
.venv\Scripts\python.exe folderLock.py --register
```

또는 별도 스크립트:
```cmd
.venv\Scripts\python.exe setup_windows.py
```

### 탐색기 통합 제거

```cmd
.venv\Scripts\python.exe folderLock.py --unregister
```

또는:
```cmd
.venv\Scripts\python.exe setup_windows.py --remove
```

---

## ⚠️ 주의사항

- **마스터 비밀번호를 분실하면 잠긴 폴더를 영원히 복구할 수 없습니다.**
  반드시 안전한 곳에 보관하세요.
- 잠금 시 원본 폴더는 **삭제**됩니다 (`.locked` 파일로 대체). 중요한 데이터는 백업 후 사용하세요.
- 비밀번호 변경 시 기존 `.locked` 파일은 새 비번으로 자동 변환되지 **않습니다**.
  이전 비번을 잊지 않도록 주의하세요.
- `.locked` 파일을 직접 편집하거나 헤더가 손상되면 복호화가 불가능합니다.
- 백신 프로그램이 레지스트리 변경을 의심할 수 있습니다. 안전한 동작이지만,
  필요 시 예외 등록을 해주세요.

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

### 폴더 우클릭에 "🔒 폴더 잠금"이 안 보임

레지스트리 등록이 안 되었거나, 등록 후 탐색기 갱신이 안 됐을 수 있습니다.

1. `pythonw folderLock.py --register` 다시 실행
2. 탐색기를 닫았다가 다시 열거나, 작업 관리자에서 `explorer.exe` 재시작
3. 그래도 안 보이면 PC 재로그인

### `.locked` 파일을 더블클릭해도 반응이 없음

레지스트리에 박힌 Python 경로나 스크립트 경로가 더 이상 유효하지 않을 수 있습니다.
위의 "탐색기 통합 다시 등록하기"를 참고해 다시 등록하세요.

### "비밀번호가 일치하지 않습니다" 메시지

- 마스터 비밀번호를 변경한 적이 있다면, 그 이전에 잠근 파일은 **이전 비밀번호**로만 해제됩니다.
- 비밀번호를 두 번 잘못 입력했다면 Caps Lock / 한영 전환을 확인하세요.

---

## 🛠 명령어 빠른 참조

| 작업 | 명령어 |
|---|---|
| 가상환경 생성 | `python -m venv .venv` |
| 의존성 설치 | `.venv\Scripts\pip install cryptography` |
| GUI 실행 (콘솔 없음) | `.venv\Scripts\pythonw.exe folderLock.py` |
| GUI 실행 (디버그) | `.venv\Scripts\python.exe folderLock.py` |
| 탐색기 통합 등록 | `.venv\Scripts\python.exe folderLock.py --register` |
| 탐색기 통합 제거 | `.venv\Scripts\python.exe folderLock.py --unregister` |
| 폴더 잠금 (CLI) | `.venv\Scripts\python.exe folderLock.py "C:\path\to\folder"` |
| 파일 해제 (CLI) | `.venv\Scripts\python.exe folderLock.py "C:\path\to\folder.locked"` |

---

## 🔐 보안 메모

- 비밀번호 검증값은 `~/.folderlock/config.json`에 저장됩니다.
- 마스터 비밀번호는 **기계 종속 키**로 obfuscate된 채 `config.json`에 저장되어,
  우클릭 잠금 시 비밀번호 입력 없이 잠금이 가능합니다.
- 다른 PC/사용자로 `config.json`을 옮기면 마스터 비밀번호 복호화가 불가능합니다.
- 각 `.locked` 파일은 자체 salt + PBKDF2 + Fernet 키로 독립 암호화됩니다.
  따라서 파일별로 잠금 시점의 비밀번호로만 해제할 수 있습니다.
