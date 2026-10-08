"""
CLI 배너 — 실행 첫 화면.

'에레렘'을 블록 문자로 직접 그린다. 터미널에서 한글은 두 칸을 차지해
글자 그대로 쓰면 박스 정렬이 깨지므로, 폭 계산을 따로 한다.

색은 ANSI로 넣되 색을 못 쓰는 환경(파이프·리다이렉트·NO_COLOR)에서는 자동으로 뺀다.
"""

from __future__ import annotations

import os
import sys

# ── 색 ────────────────────────────────────────────────────────────────
C = {
    "r": "\033[0m", "b": "\033[1m", "d": "\033[2m",
    "cy": "\033[36m", "CY": "\033[96m",
    "bl": "\033[34m", "BL": "\033[94m",
    "ye": "\033[33m", "YE": "\033[93m",
    "gr": "\033[32m", "GR": "\033[92m",
    "ma": "\033[35m", "MA": "\033[95m",
    "wh": "\033[37m", "WH": "\033[97m",
    "gy": "\033[90m",
}


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:                      # Windows 10+ 가상 터미널 활성화
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


def paint(text: str, enable: bool) -> str:
    for k, v in C.items():
        text = text.replace("{" + k + "}", v if enable else "")
    return text


# ══════════════════════════════════════════════════════════════════════
#  '에레렘' 블록 글꼴 — 한 글자당 9행
#    에 = ㅇ + ㅔ        레 = ㄹ + ㅔ        렘 = ㄹ + ㅔ + 받침 ㅁ
# ══════════════════════════════════════════════════════════════════════






# ══════════════════════════════════════════════════════════════════════
#  1. 블록 한글 + 속도선 (정면)
# ══════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════
#  2. 왼쪽 속도선 + 블록 한글 (씽씽 달리는 느낌)
# ══════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════
#  실행 첫 화면
# ══════════════════════════════════════════════════════════════════════
def _b3() -> str:
    return "\n".join([
        "",
        "{d}{cy}»»» {r}{CY}███████ ██████  ███████ ██████  ███████ ███    ███{r}",
        "{d}{cy} »» {r}{CY}██      ██   ██ ██      ██   ██ ██      ████  ████{r}",
        "{d}{cy}  » {r}{cy}█████   ██████  █████   ██████  █████   ██ ████ ██{r}",
        "{d}{cy}    {r}{cy}██      ██   ██ ██      ██   ██ ██      ██  ██  ██{r}",
        "{d}{cy}    {r}{bl}███████ ██   ██ ███████ ██   ██ ███████ ██      ██{r}",
        "",
        "{b}{WH}      에 레 렘{r}{gy}  ·  C L A U D E   D E S K T O P   P A R S E R{r}",
        "",
    ])


# ══════════════════════════════════════════════════════════════════════
#  4. 박스 프레임 + 진행 게이지 (도구다운 단정함)
# ══════════════════════════════════════════════════════════════════════


# ══════════════════════════════════════════════════════════════════════
#  5. 미니멀 원라인 (빠르게 자주 돌릴 때)
# ══════════════════════════════════════════════════════════════════════


BANNERS = {1: _b3}
DEFAULT = 1


def render(which: int = DEFAULT, color: bool | None = None) -> str:
    if color is None:
        color = supports_color()
    fn = BANNERS.get(which, BANNERS[DEFAULT])
    return paint(fn(), color).rstrip("\n")


def show(which: int = DEFAULT, color: bool | None = None) -> None:
    print(render(which, color))


if __name__ == "__main__":
    # 기본은 실행할 때 실제로 뜨는 배너 하나만 보여 준다.
    #   python aifp/banner.py            기본 배너
    #   python aifp/banner.py 1          1번 배너
    #   python aifp/banner.py --all      전체 미리보기
    #   python aifp/banner.py --color    색을 강제로 켠다 (파이프·리다이렉트에서도)
    args = sys.argv[1:]
    color = True if "--color" in args else None
    picked = [int(a) for a in args if a.isdigit() and int(a) in BANNERS]

    if "--all" in args:
        for i in sorted(BANNERS):
            print("\n" + "─" * 72)
            print(f"  [{i}]")
            print("─" * 72)
            print(render(i, color=color))
        print()
    else:
        print(render(picked[0] if picked else DEFAULT, color=color))
