# LM Studio Forensic Parser

## 1. Overview

Windows의 LM Studio forensic artifact를 읽기 전용으로 분석하는 파서입니다. Offline image, 추출 directory 및 현재 Windows Live 환경에서 사용자 행위와 대화 정보를 분석하고 `timeline.csv`, `recovered_conversations.csv`를 생성합니다.

## 2. Requirements

- 개발·검증 기준: Python 3.12.13, repository root의 `.venv312`
- Windows Live Mode: Windows에서만 실행 가능

| 용도 | Dependency |
|---|---|
| NTFS image 분석 | `dissect.ntfs`, `dissect.volume` |
| EWF 입력 | 위 항목 + `dissect.evidence` |
| BitLocker 볼륨 해제 | 위 입력별 항목 + `dissect.fve` (검증 버전: 4.6) |

## 3. Supported Inputs

- DD / RAW / IMG
- EWF: `.e01`, `.ex01`, `.s01`, `.l01`
- Split RAW/DD: 첫 `.001` segment 지정, 연속된 segment 필요
- Directory: `.lmstudio`, 사용자 profile, `Users`를 포함한 Windows root 또는 추출 artifact directory
- 단일 artifact file
- Windows Live Mode

이미지의 filesystem 분석은 NTFS를 지원합니다.

## 4. Usage

아래 명령은 repository root의 PowerShell에서 실행합니다. 입력 및 수집 대상과 겹치지 않는 별도 출력 폴더를 지정합니다.

### Offline image / Directory

```powershell
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py evidence.E01 --output C:\ForensicOutput\lmstudio
```

`evidence.E01` 대신 directory 또는 단일 artifact 경로를 지정할 수 있습니다. `--validate`를 추가하면 재분석을 통한 결과 검증을 수행합니다. `--before <PATH>`는 동일 대상의 명시적 이전 snapshot을 함께 분석하는 선택 옵션입니다.

### Windows Live Mode

```powershell
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py --live --output C:\ForensicOutput\lmstudio_live
```

로컬 사용자 profile의 `.lmstudio`와 `.lmstudio-home-pointer`를 확인합니다. `--live-root <WindowsRoot>`로 `Users`를 포함한 로컬 Windows root를 지정할 수 있습니다. `--live`는 positional input, `--before`, `--validate`, BitLocker credential 옵션과 함께 사용할 수 없습니다.

### BitLocker image

```powershell
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py evidence.E01 --bitlocker-recovery-prompt --output C:\ForensicOutput\lmstudio
```

DD/RAW/IMG, EWF, Split RAW 내부 BitLocker 볼륨을 authorized credential로 읽기 전용 해제합니다. 복호화 stream을 기존 filesystem 분석에 연결하며 전체 decrypted DD는 생성하지 않습니다. 실제 clear-key protector가 있으면 별도 옵션 없이 해제를 시도합니다.

| Credential | 옵션 |
|---|---|
| Recovery Password | `--bitlocker-recovery-prompt` |
| Passphrase | `--bitlocker-passphrase-prompt` |
| BEK file | `--bitlocker-bek <FILE>` |
| Raw binary FVEK (16/32/64 bytes) | `--bitlocker-fvek <FILE>` |

Credential 옵션은 하나만 지정할 수 있습니다. Recovery Password와 Passphrase는 화면에 표시되지 않는 prompt로 입력합니다. 키가 없거나 해제에 실패한 partition은 건너뛰며, 분석 가능한 NTFS 볼륨이 없으면 오류로 종료합니다.

## 5. Output

| 파일 | 내용 |
|---|---|
| `timeline.csv` | LM Studio 사용자 행위, 판정 및 근거를 담은 7열 타임라인 |
| `recovered_conversations.csv` | 복구된 대화·메시지 정보를 담은 10열 CSV |
| `validation.json` | `--validate` 검증 성공 시 생성되는 결과 |

CSV는 UTF-8-SIG와 CRLF를 사용하며, 누락 값은 `-`로 표시합니다.

## 6. Artifact Display

`Artifact_path`와 `Artifact_details`는 의미가 같은 반복 근거를 대표값과 `동일 근거=N건`으로 정리합니다. 내부 Candidate Fact와 원본 forensic evidence는 삭제하지 않으며, 서로 다른 의미의 근거는 개별 표시를 유지합니다. 건수는 묶인 Fact 수이며 독립증거 수나 사용자 행위 횟수를 뜻하지 않습니다.

## 7. Limitations

- Live Mode는 filesystem snapshot이 아니며, 파일 간 시점 일관성을 보장하지 않습니다.
- Live Mode에서는 raw MFT·USN history와 삭제 파일 복구를 수행하지 않습니다. 권한 부족, 잠금 또는 분석 중 변경된 파일은 접근·본문 분석이 제한됩니다.
- BitLocker에는 사용 가능한 authorized key material 또는 실제 clear-key protector가 필요합니다. TPM extraction, cracking, bypass는 지원하지 않습니다.
- NTFS image 내부에서 재배치된 LM Studio Home의 drive-letter 자동 mapping은 지원하지 않습니다.
- 지원하지 않는 filesystem, 손상된 image 및 누락된 history는 분석·복구 범위를 제한합니다.

## 8. Validation

`--validate`는 동일 입력을 두 번 분석해 CSV 형식과 동일성, 민감정보 노출 및 이미지 크기·수정 시각 불변을 검사합니다. Live Mode에서는 사용할 수 없습니다.

```powershell
.\.venv312\Scripts\python.exe -m py_compile LMstudio_parser\lmstudio_parser.py
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py --self-test
```
