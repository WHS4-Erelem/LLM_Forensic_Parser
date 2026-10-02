"""elelem LLM Forensic Parser — PyQt6 메인 윈도우.

흐름: Case Setup → Evidence Setup → Analysis Progress → Results Workspace.
결과는 기존 통합 Runner 가 만든 파일에서만 읽는다. GUI 는 새 포렌식 판정을 만들지 않는다.
"""
from __future__ import annotations

import os
import subprocess
import sys

from PyQt6.QtCore import QSortFilterProxyModel, Qt, QUrl, pyqtSlot
from PyQt6.QtGui import QColor, QDesktopServices, QFont, QStandardItem, QStandardItemModel
from PyQt6.QtWidgets import (QAbstractItemView, QButtonGroup, QCheckBox, QFileDialog, QFrame,
                             QGridLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget,
                             QListWidgetItem, QMessageBox, QPlainTextEdit, QProgressBar,
                             QPushButton, QRadioButton, QScrollArea, QSizePolicy, QSplitter,
                             QStackedWidget, QTableView, QTabWidget, QTextBrowser, QVBoxLayout,
                             QWidget)

from case_manager import CaseInfo
from integration_runner import EXIT_MEANING, RUNNER, IntegrationRunner, registry_parsers
from result_loader import (CONVERSATIONS_CSV, DISPLAY_NAMES, EMPTY, REPORT_JSON, ST_COMPLETED,
                           ST_FAILED, ST_LIMITED, ST_NO_RESULT, ST_SKIPPED, TIMELINE_CSV,
                           TIMELINE_VIEW_COLUMNS, UNIFIED_DB, VERDICT_CONFIRMED, VERDICT_SUSPECTED,
                           ResultBundle, ResultLoadError, cell, evidence_dir_conflict,
                           find_result_dirs)

HERE = os.path.dirname(os.path.abspath(__file__))
TEAM = "elelem"
STATUS_BADGE = {"success": ("완료", "BadgeGreen"), "running": ("진행", "BadgeBlue"),
                "waiting": ("대기", "BadgeNeutral"), "skipped": ("미실행", "BadgeNeutral"),
                "failed": ("실패", "BadgeRed"), "contract_violation": ("계약 위반", "BadgeRed"),
                "normalization_error": ("정규화 실패", "BadgeRed"), "db_error": ("DB 오류", "BadgeRed"),
                "output_error": ("출력 오류", "BadgeRed"), "warning": ("주의", "BadgeYellow"),
                "integration": ("통합", "BadgeRed"), "-": ("정보 없음", "BadgeNeutral"),
                # 결과 화면의 파서 상태 (result_loader.display_status 가 실제 근거로 정한 값)
                ST_COMPLETED: ("Completed", "BadgeGreen"), ST_NO_RESULT: ("No Result", "BadgeNeutral"),
                ST_FAILED: ("Failed", "BadgeRed"), ST_SKIPPED: ("Skipped", "BadgeNeutral"),
                ST_LIMITED: ("Limited", "BadgeYellow")}
VERDICT_BADGE = {VERDICT_CONFIRMED: "BadgeGreen", VERDICT_SUSPECTED: "BadgeYellow"}
VERDICT_COLOR = {VERDICT_CONFIRMED: "#26734d", VERDICT_SUSPECTED: "#8a6400"}


# --------------------------------------------------------------------- 공통 위젯
def badge(text, kind="BadgeNeutral"):
    label = QLabel(text)
    label.setObjectName(kind)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)
    return label


def panel(title=None, badge_widget=None):
    """(frame, body_layout). Panel = 흰 배경 + 얇은 Border."""
    frame = QFrame()
    frame.setObjectName("Panel")
    outer = QVBoxLayout(frame)
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(0)
    if title is not None:
        header = QWidget()
        header.setObjectName("PanelHeader")
        row = QHBoxLayout(header)
        row.setContentsMargins(12, 8, 12, 8)
        caption = QLabel(title)
        caption.setObjectName("PanelTitle")
        row.addWidget(caption)
        row.addStretch(1)
        if badge_widget is not None:
            row.addWidget(badge_widget)
        outer.addWidget(header)
    body = QVBoxLayout()
    body.setContentsMargins(12, 12, 12, 12)
    body.setSpacing(9)
    outer.addLayout(body)
    return frame, body


def section_label(text):
    label = QLabel(text.upper())
    label.setObjectName("SectionLabel")
    return label


def mono_label(text, wrap=True):
    label = QLabel(text)
    label.setObjectName("Mono")
    label.setWordWrap(wrap)
    label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return label


def muted(text):
    label = QLabel(text)
    label.setObjectName("Muted")
    label.setWordWrap(True)
    return label


def field_row(caption, widget, button=None):
    box = QVBoxLayout()
    box.setSpacing(4)
    box.addWidget(section_label(caption))
    line = QHBoxLayout()
    line.setSpacing(6)
    line.addWidget(widget, 1)
    if button is not None:
        line.addWidget(button)
    box.addLayout(line)
    return box


def metric_card(label_text, value_text):
    card = QFrame()
    card.setObjectName("MetricCard")
    box = QVBoxLayout(card)
    box.setContentsMargins(12, 10, 12, 10)
    box.setSpacing(2)
    value = QLabel(value_text)
    value.setObjectName("MetricValue")
    caption = QLabel(label_text)
    caption.setObjectName("MetricLabel")
    caption.setWordWrap(True)
    box.addWidget(value)
    box.addWidget(caption)
    return card


class StatusRow(QWidget):
    """'● 이름  [상태]' 한 줄. 실제로 확인된 상태만 넣는다."""

    def __init__(self, name, status="waiting", detail=""):
        super().__init__()
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 3, 0, 3)
        row.setSpacing(8)
        self.dot = QLabel("●")
        self.dot.setFixedWidth(12)
        self.name = QLabel(name)
        self.detail = QLabel(detail)
        self.detail.setObjectName("Muted")
        self.badge = badge(*STATUS_BADGE.get(status, STATUS_BADGE["waiting"]))
        row.addWidget(self.dot)
        row.addWidget(self.name)
        row.addStretch(1)
        row.addWidget(self.detail)
        row.addWidget(self.badge)
        self.set_status(status, detail)

    def set_status(self, status, detail=None):
        text, kind = STATUS_BADGE.get(status, STATUS_BADGE["waiting"])
        self.badge.setText(text)
        self.badge.setObjectName(kind)
        self.badge.setStyleSheet("")                     # objectName 변경 반영
        self.badge.style().unpolish(self.badge)
        self.badge.style().polish(self.badge)
        colors = {"BadgeGreen": "#26734d", "BadgeBlue": "#2166a5", "BadgeYellow": "#8a6400",
                  "BadgeRed": "#a13a3a", "BadgeNeutral": "#b9c6cb", "BadgeTeal": "#1c5f70"}
        self.dot.setStyleSheet("color: %s;" % colors.get(kind, "#b9c6cb"))
        if detail is not None:
            self.detail.setText(detail)


class TableFilterProxy(QSortFilterProxyModel):
    """모든 열에 대한 대소문자 무시 부분 일치 (Global Search 용)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._needle = ""

    def set_needle(self, text):
        self._needle = (text or "").strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, row, parent):
        if not self._needle:
            return True
        model = self.sourceModel()
        for column in range(model.columnCount()):
            value = model.data(model.index(row, column, parent)) or ""
            if self._needle in str(value).lower():
                return True
        return False


def make_table():
    view = QTableView()
    view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    view.setAlternatingRowColors(True)
    view.setSortingEnabled(True)
    view.setWordWrap(False)
    view.verticalHeader().setVisible(False)
    view.verticalHeader().setDefaultSectionSize(24)
    view.horizontalHeader().setHighlightSections(False)
    view.horizontalHeader().setStretchLastSection(True)
    return view


def fill_model(columns, rows, display=True):
    """QStandardItemModel 로 채운다. 각 행의 원본 dict 은 UserRole 에 보관한다."""
    model = QStandardItemModel()
    model.setHorizontalHeaderLabels([DISPLAY_NAMES.get(c, c) if display else c for c in columns])
    for row in rows:
        items = []
        for column in columns:
            item = QStandardItem(cell(row, column))
            item.setData(row, Qt.ItemDataRole.UserRole)
            if column == "Verdict" and cell(row, column) in VERDICT_COLOR:
                item.setForeground(QColor(VERDICT_COLOR[cell(row, column)]))
                font = QFont()
                font.setBold(True)
                item.setFont(font)
            items.append(item)
        model.appendRow(items)
    return model


def open_in_explorer(path):
    """폴더/파일 위치를 탐색기로 연다 (읽기 전용 동작). 성공 여부 반환."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        return False
    if sys.platform.startswith("win"):
        if os.path.isdir(path):
            os.startfile(path)                                       # noqa: S606 - 사용자 조작으로 폴더 열기
        else:
            subprocess.Popen(["explorer", "/select,", path])         # noqa: S603,S607
        return True
    return QDesktopServices.openUrl(QUrl.fromLocalFile(path))


# ------------------------------------------------------------------ 메인 윈도우
class MainWindow(QWidget):
    """TopBar + 4단계 QStackedWidget."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("%s LLM Forensic Parser" % TEAM)
        self.resize(1480, 920)
        self.case = CaseInfo()
        self.bundle = None
        self.runner = IntegrationRunner(self)
        self.parsers = registry_parsers()
        self.parser_checks = {}
        self.module_rows = {}
        self.validation_rows = {}
        self._last_out_dir = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        root.addWidget(self._build_topbar())

        self.stack = QStackedWidget()
        self.stack.setObjectName("CentralArea")
        root.addWidget(self.stack, 1)
        self.stack.addWidget(self._build_case_page())        # 0
        self.stack.addWidget(self._build_evidence_page())    # 1
        self.stack.addWidget(self._build_progress_page())    # 2
        self.stack.addWidget(self._build_results_page())     # 3

        self.runner.logLine.connect(self._append_log)
        self.runner.stageChanged.connect(self._on_stage)
        self.runner.parserStatus.connect(self._on_parser_status)
        self.runner.evidenceInfo.connect(self._on_evidence_info)
        self.runner.finished.connect(self._on_finished)
        self._revalidate()                                   # 위젯이 모두 만들어진 뒤에 검증한다

    # ----------------------------------------------------------------- TopBar
    def _build_topbar(self):
        bar = QFrame()
        bar.setObjectName("TopBar")
        row = QHBoxLayout(bar)
        row.setContentsMargins(16, 10, 16, 10)
        row.setSpacing(12)

        logo = QLabel("EL")
        logo.setObjectName("LogoBox")
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        row.addWidget(logo)

        title_box = QVBoxLayout()
        title_box.setSpacing(0)
        title = QLabel("%s LLM Forensic Parser" % TEAM)
        title.setObjectName("AppTitle")
        subtitle = QLabel("Integrated LLM Artifact Analysis")
        subtitle.setObjectName("AppSubtitle")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        row.addLayout(title_box)
        row.addStretch(1)

        self.search_box = QLineEdit()
        self.search_box.setObjectName("GlobalSearch")
        self.search_box.setPlaceholderText("검색: 행위 · UUID · 경로 · 파일명 · 대화 내용")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.textChanged.connect(self._on_search)
        self.search_box.setEnabled(False)
        row.addWidget(self.search_box)
        row.addStretch(1)

        self.btn_back = QPushButton("이전 단계")
        self.btn_back.clicked.connect(self._go_back)
        self.btn_back.setVisible(False)
        row.addWidget(self.btn_back)

        self.btn_run = QPushButton("분석 실행")
        self.btn_run.setObjectName("Primary")
        self.btn_run.clicked.connect(self._on_run_clicked)
        row.addWidget(self.btn_run)
        return bar

    # ------------------------------------------------------------ 1. Case Setup
    def _build_case_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(24, 24, 24, 24)
        outer.addStretch(1)

        frame, body = panel("사건 정보")
        frame.setMaximumWidth(720)
        self.in_case_name = QLineEdit()
        self.in_case_number = QLineEdit()
        self.in_examiner = QLineEdit()
        self.in_notes = QPlainTextEdit()
        self.in_notes.setFixedHeight(96)
        body.addWidget(muted("사건 정보는 Parser 결과에 쓰지 않고 결과 폴더의 case_info.json 으로만 저장됩니다."))
        body.addLayout(field_row("사건명", self.in_case_name))
        body.addLayout(field_row("사건번호", self.in_case_number))
        body.addLayout(field_row("분석가", self.in_examiner))
        body.addLayout(field_row("메모", self.in_notes))

        buttons = QHBoxLayout()
        start = QPushButton("새 분석 시작")
        start.setObjectName("Primary")
        start.clicked.connect(self._start_new_case)
        load = QPushButton("기존 분석 불러오기")
        load.clicked.connect(self._load_existing)
        buttons.addStretch(1)
        buttons.addWidget(load)
        buttons.addWidget(start)
        body.addLayout(buttons)

        center = QHBoxLayout()
        center.addStretch(1)
        center.addWidget(frame)
        center.addStretch(1)
        outer.addLayout(center)
        outer.addStretch(2)
        return page

    # -------------------------------------------------------- 2. Evidence Setup
    def _build_evidence_page(self):
        page = QWidget()
        outer = QHBoxLayout(page)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(12)

        left, body = panel("분석 입력")
        left.setMinimumWidth(430)
        left.setMaximumWidth(560)
        self.in_image = QLineEdit()
        self.in_image.setPlaceholderText("E01 또는 DD/RAW 이미지 파일")
        self.in_image.textChanged.connect(self._revalidate)
        browse_image = QPushButton("찾아보기")
        browse_image.clicked.connect(self._pick_image)
        self.in_out = QLineEdit()
        self.in_out.setPlaceholderText("결과를 저장할 폴더 (증거와 다른 위치)")
        self.in_out.textChanged.connect(self._revalidate)
        browse_out = QPushButton("찾아보기")
        browse_out.clicked.connect(self._pick_out)
        body.addLayout(field_row("증거 이미지", self.in_image, browse_image))
        body.addLayout(field_row("결과 폴더", self.in_out, browse_out))

        body.addWidget(section_label("Parser 모드"))
        self.rb_all = QRadioButton("Run All (등록된 파서 전체 실행)")
        self.rb_manual = QRadioButton("Manual Selection (--only)")
        self.rb_all.setChecked(True)
        group = QButtonGroup(page)
        group.addButton(self.rb_all)
        group.addButton(self.rb_manual)
        self.rb_all.toggled.connect(self._on_mode_changed)
        body.addWidget(self.rb_all)
        body.addWidget(self.rb_manual)
        body.addWidget(muted("통합 Runner 에 서비스 자동 탐지 기능은 없습니다. 선택하지 않은 파서는 실행되지 않습니다."))

        soft = QFrame()
        soft.setObjectName("PanelSoft")
        picks = QVBoxLayout(soft)
        picks.setContentsMargins(10, 10, 10, 10)
        picks.setSpacing(4)
        for parser_id, model in self.parsers:
            check = QCheckBox("%s  (%s)" % (parser_id, model))
            check.setChecked(True)
            check.setEnabled(False)
            check.toggled.connect(self._revalidate)
            self.parser_checks[parser_id] = check
            picks.addWidget(check)
        pick_buttons = QHBoxLayout()
        self.btn_all = QPushButton("전체 선택")
        self.btn_all.clicked.connect(lambda: self._set_all_checks(True))
        self.btn_none = QPushButton("선택 해제")
        self.btn_none.clicked.connect(lambda: self._set_all_checks(False))
        self.btn_all.setEnabled(False)
        self.btn_none.setEnabled(False)
        pick_buttons.addWidget(self.btn_all)
        pick_buttons.addWidget(self.btn_none)
        pick_buttons.addStretch(1)
        picks.addLayout(pick_buttons)
        body.addWidget(soft)

        self.cb_quick = QCheckBox("--quick (세그먼트 SHA-256 생략 — 무결성 대조 불가)")
        self.cb_quick.toggled.connect(self._revalidate)
        body.addWidget(self.cb_quick)
        body.addStretch(1)
        outer.addWidget(left)

        right, rbody = panel("입력 검증")
        for key, name in (("evidence", "Evidence Path"), ("signature", "Image Recognition"),
                          ("output", "Output Folder"), ("parsers", "Parser Selection"),
                          ("runner", "Integration Runner"), ("readonly", "Read-only")):
            row = StatusRow(name, "waiting", "")
            self.validation_rows[key] = row
            rbody.addWidget(row)
        rbody.addWidget(muted("각 항목은 실제로 확인한 내용만 '완료'로 표시합니다. "
                              "이미지 내부 파일시스템은 이 단계에서 열지 않으므로 검증 대상이 아닙니다."))
        rbody.addStretch(1)
        outer.addWidget(right, 1)
        return page

    # ------------------------------------------------------ 3. Analysis Progress
    def _build_progress_page(self):
        page = QWidget()
        outer = QHBoxLayout(page)
        outer.setContentsMargins(16, 16, 16, 16)
        outer.setSpacing(12)

        left, body = panel("분석 모듈")
        left.setMinimumWidth(320)
        left.setMaximumWidth(400)
        modules = [("evidence", "Evidence")] + [(pid, pid) for pid, _ in self.parsers] + \
                  [("normalization", "Normalization")]
        for key, name in modules:
            row = StatusRow(name, "waiting")
            self.module_rows[key] = row
            body.addWidget(row)
        body.addSpacing(8)
        body.addWidget(section_label("진행 상태"))
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)                      # Runner 가 %를 내지 않으므로 indeterminate
        self.progress.setTextVisible(False)
        body.addWidget(self.progress)
        self.lbl_stage = muted("대기 중")
        body.addWidget(self.lbl_stage)
        body.addWidget(muted("서비스별 Parser 결과는 내부 공통 Schema로 정규화한 뒤 Timeline, "
                             "Conversations 및 Artifact 결과 화면에 표시됩니다."))
        body.addStretch(1)
        self.btn_cancel = QPushButton("분석 중단")
        self.btn_cancel.clicked.connect(self.runner.cancel)
        self.btn_cancel.setEnabled(False)
        body.addWidget(self.btn_cancel)
        outer.addWidget(left)

        right, rbody = panel("실행 로그 (stdout / stderr)")
        self.log_view = QPlainTextEdit()
        self.log_view.setObjectName("LogView")
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(20000)
        rbody.addWidget(self.log_view, 1)
        self.btn_show_results = QPushButton("결과 화면 보기")
        self.btn_show_results.setObjectName("Primary")
        self.btn_show_results.setEnabled(False)
        self.btn_show_results.clicked.connect(lambda: self.stack.setCurrentIndex(3))
        log_buttons = QHBoxLayout()
        log_buttons.addStretch(1)
        log_buttons.addWidget(self.btn_show_results)
        rbody.addLayout(log_buttons)
        outer.addWidget(right, 1)
        return page

    # ---------------------------------------------------- 4. Results Workspace
    def _build_results_page(self):
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(16, 16, 16, 16)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        outer.addWidget(splitter, 1)

        # ----- 왼쪽: 사건 / 증거 / 서비스 / 단계
        left, lbody = panel("분석 개요")
        left.setMinimumWidth(240)
        self.lbl_case = muted("-")
        self.lbl_evidence = mono_label("-")
        lbody.addWidget(section_label("사건"))
        lbody.addWidget(self.lbl_case)
        lbody.addWidget(section_label("증거"))
        lbody.addWidget(self.lbl_evidence)
        lbody.addWidget(section_label("실행된 서비스"))
        self.services_box = QVBoxLayout()
        self.services_box.setSpacing(0)
        lbody.addLayout(self.services_box)
        lbody.addWidget(section_label("처리 단계"))
        self.steps_box = QVBoxLayout()
        self.steps_box.setSpacing(0)
        lbody.addLayout(self.steps_box)
        lbody.addStretch(1)
        self.btn_open_result = QPushButton("결과 폴더 열기")
        self.btn_open_result.clicked.connect(self._open_result_dir)
        lbody.addWidget(self.btn_open_result)
        splitter.addWidget(left)

        # ----- 가운데: 결과 탭
        self.result_badge = badge("-", "BadgeTeal")
        center, cbody = panel("분석 결과", self.result_badge)
        self.tabs = QTabWidget()
        cbody.addWidget(self.tabs, 1)

        # Overview
        self.tab_overview = QWidget()
        overview_outer = QVBoxLayout(self.tab_overview)
        overview_outer.setContentsMargins(12, 12, 12, 12)
        self.overview_notice = self._empty_notice()
        overview_outer.addWidget(self.overview_notice)
        self.metrics_grid = QGridLayout()
        self.metrics_grid.setSpacing(9)
        overview_outer.addLayout(self.metrics_grid)
        self.overview_notes = QTextBrowser()
        self.overview_notes.setOpenExternalLinks(False)
        overview_outer.addWidget(self.overview_notes, 1)
        self.tabs.addTab(self.tab_overview, "Overview")

        # Timeline
        self.timeline_view = make_table()
        self.timeline_model = QStandardItemModel()
        self.timeline_proxy = TableFilterProxy(self)
        self.timeline_empty = self._empty_notice()
        self.tabs.addTab(self._wrap(self.timeline_view, self.timeline_empty), "Timeline")

        # Conversations
        conv = QWidget()
        conv_layout = QHBoxLayout(conv)
        conv_layout.setContentsMargins(12, 12, 12, 12)
        conv_split = QSplitter(Qt.Orientation.Horizontal)
        self.session_list = QListWidget()
        self.session_list.setMinimumWidth(240)
        self.session_list.currentRowChanged.connect(self._on_session_changed)
        self.message_view = QTextBrowser()
        self.message_view.setOpenExternalLinks(False)
        conv_split.addWidget(self.session_list)
        conv_split.addWidget(self.message_view)
        conv_split.setSizes([280, 700])
        conv_layout.addWidget(conv_split)
        self.tabs.addTab(conv, "Conversations")

        # Artifacts
        self.artifact_view = make_table()
        self.artifact_proxy = TableFilterProxy(self)
        self.tabs.addTab(self._wrap(self.artifact_view), "Artifacts / Files")

        # Errors
        errors = QWidget()
        errors_layout = QVBoxLayout(errors)
        errors_layout.setContentsMargins(12, 12, 12, 12)
        self.error_view = make_table()
        self.error_proxy = TableFilterProxy(self)
        errors_layout.addWidget(self.error_view, 2)
        errors_layout.addWidget(section_label("Analysis Limitations"))
        self.limitations_view = QTextBrowser()
        errors_layout.addWidget(self.limitations_view, 1)
        self.tabs.addTab(errors, "Errors & Limitations")
        # 탭이 모두 만들어진 뒤에 연결한다 (addTab 이 currentChanged 를 바로 보낸다)
        self.tabs.currentChanged.connect(lambda _: self._on_search(self.search_box.text()))
        splitter.addWidget(center)

        # ----- 오른쪽: 근거 상세
        self.detail_badge = badge("-", "BadgeNeutral")
        right, rbody = panel("근거 상세", self.detail_badge)
        right.setMinimumWidth(300)
        self.detail_view = QTextBrowser()
        self.detail_view.setOpenExternalLinks(False)
        rbody.addWidget(self.detail_view, 1)
        self.btn_open_artifact = QPushButton("근거 파일 위치 열기")
        self.btn_open_artifact.setEnabled(False)
        self.btn_open_artifact.clicked.connect(self._open_artifact_path)
        rbody.addWidget(self.btn_open_artifact)
        btn_open_result2 = QPushButton("결과 폴더 열기")
        btn_open_result2.clicked.connect(self._open_result_dir)
        rbody.addWidget(btn_open_result2)
        splitter.addWidget(right)

        splitter.setSizes([260, 900, 330])
        self._detail_path = ""
        self._set_detail("<p class='muted'>Timeline 또는 Errors 표에서 행을 선택하면 근거가 여기에 표시됩니다.</p>")
        return page

    @staticmethod
    def _wrap(widget, empty_label=None):
        """표를 감싼다. empty_label 을 주면 '0건 안내' 를 표 위에 둘 수 있다 (기본 숨김)."""
        holder = QWidget()
        box = QVBoxLayout(holder)
        box.setContentsMargins(12, 12, 12, 12)
        box.setSpacing(9)
        if empty_label is not None:
            empty_label.setVisible(False)
            box.addWidget(empty_label)
        box.addWidget(widget)
        return holder

    @staticmethod
    def _empty_notice():
        """0건 / 분석 제한 안내용 라벨 (Panel Soft 배경). 실패 표시가 아니다."""
        label = QLabel("")
        label.setObjectName("PanelSoft")
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        label.setContentsMargins(12, 10, 12, 10)
        label.setVisible(False)
        return label

    # ------------------------------------------------------------------ 흐름
    def _start_new_case(self):
        self.case = CaseInfo(case_name=self.in_case_name.text().strip(),
                             case_number=self.in_case_number.text().strip(),
                             examiner=self.in_examiner.text().strip(),
                             notes=self.in_notes.toPlainText().strip())
        self.stack.setCurrentIndex(1)
        self.btn_back.setVisible(True)
        self._revalidate()

    def _go_back(self):
        index = self.stack.currentIndex()
        if self.runner.is_running():
            QMessageBox.information(self, "분석 진행 중", "분석이 끝나거나 중단된 뒤에 이동할 수 있습니다.")
            return
        target = 1 if index == 3 and self.bundle is not None else max(0, index - 1)
        self.stack.setCurrentIndex(target)
        self.btn_back.setVisible(target > 0)
        self._update_run_button()

    def _pick_image(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "증거 이미지 선택", "", "디스크 이미지 (*.E01 *.e01 *.dd *.raw *.img *.001);;모든 파일 (*)")
        if path:
            self.in_image.setText(os.path.normpath(path))

    def _pick_out(self):
        path = QFileDialog.getExistingDirectory(self, "결과 폴더 선택", self.in_out.text() or "")
        if path:
            self.in_out.setText(os.path.normpath(path))

    def _on_mode_changed(self, _checked):
        manual = self.rb_manual.isChecked()
        for check in self.parser_checks.values():
            check.setEnabled(manual)
        self.btn_all.setEnabled(manual)
        self.btn_none.setEnabled(manual)
        self._revalidate()

    def _set_all_checks(self, value):
        for check in self.parser_checks.values():
            check.setChecked(value)

    def selected_parsers(self):
        if self.rb_all.isChecked():
            return None                                   # --only 없이 전체 실행
        return [pid for pid, check in self.parser_checks.items() if check.isChecked()]

    # ------------------------------------------------------------- 입력 검증
    def _revalidate(self):
        image = self.in_image.text().strip()
        out_dir = self.in_out.text().strip()
        ok_image = bool(image) and os.path.isfile(image)
        self.validation_rows["evidence"].set_status(
            "success" if ok_image else ("failed" if image else "waiting"),
            "경로 확인됨" if ok_image else ("파일이 없음" if image else "이미지를 선택하세요"))

        kind, detail = self._image_kind(image) if ok_image else ("", "이미지 선택 후 확인")
        self.validation_rows["signature"].set_status("success" if kind else "waiting", detail)

        ok_out = bool(out_dir) and self._out_writable(out_dir)
        # 증거 폴더(또는 그 하위)에 결과를 쓰면 파서가 출력을 거부하고 증거 폴더도 오염된다 → 실행 차단
        conflict = bool(image) and bool(out_dir) and evidence_dir_conflict(image, out_dir)
        if conflict:
            self.validation_rows["output"].set_status(
                "failed", "결과 폴더가 증거 폴더 내부입니다 — 다른 위치를 선택하세요")
        else:
            self.validation_rows["output"].set_status(
                "success" if ok_out else ("failed" if out_dir else "waiting"),
                "쓰기 가능" if ok_out else ("쓸 수 없는 경로" if out_dir else "결과 폴더를 선택하세요"))

        selected = self.selected_parsers()
        ok_parsers = selected is None or bool(selected)
        self.validation_rows["parsers"].set_status(
            "success" if ok_parsers else "failed",
            "전체 %d개 실행" % len(self.parsers) if selected is None else
            ("%d개 선택" % len(selected) if selected else "최소 1개를 선택하세요"))

        ok_runner = os.path.isfile(RUNNER)
        self.validation_rows["runner"].set_status("success" if ok_runner else "failed",
                                                  "llm_forensic.py 확인됨" if ok_runner else "Runner 를 찾을 수 없음")
        self.validation_rows["readonly"].set_status(
            "success", "증거는 읽기만 하고 결과는 결과 폴더에만 생성" if not self.cb_quick.isChecked()
            else "읽기 전용 · --quick 으로 해시 생략")
        self._ready = ok_image and bool(kind) and ok_out and not conflict and ok_parsers and ok_runner
        self._out_conflict = conflict
        self._update_run_button()

    @staticmethod
    def _image_kind(path):
        """앞 8바이트만 읽어 E01 인지 확인 (원본은 읽기만 한다)."""
        try:
            with open(path, "rb") as fh:
                head = fh.read(8)
        except OSError as exc:
            return "", "읽을 수 없음 (%s)" % exc.strerror
        if head == b"EVF\x09\x0d\x0a\xff\x00":
            return "e01", "E01 시그니처 확인됨"
        return "raw", "E01 시그니처 없음 → DD/RAW 로 처리됨"

    @staticmethod
    def _out_writable(path):
        probe = path if os.path.isdir(path) else os.path.dirname(os.path.abspath(path))
        return os.path.isdir(probe) and os.access(probe, os.W_OK)

    def _update_run_button(self):
        if not hasattr(self, "stack"):                       # 아직 페이지를 만드는 중
            return
        page = self.stack.currentIndex()
        if self.runner.is_running():
            self.btn_run.setText("분석 중...")
            self.btn_run.setEnabled(False)
            return
        self.btn_run.setText("분석 실행")
        self.btn_run.setEnabled(page in (1, 2) and getattr(self, "_ready", False))

    # ---------------------------------------------------------------- 실행
    def _on_run_clicked(self):
        if self.stack.currentIndex() == 0:
            self._start_new_case()
            return
        image, out_dir = self.in_image.text().strip(), self.in_out.text().strip()
        if getattr(self, "_out_conflict", False):
            QMessageBox.warning(self, "결과 폴더 위치 확인",
                                "결과 폴더가 증거 폴더 내부에 있습니다.\n"
                                "증거와 다른 위치의 폴더를 선택하세요.")
            return
        if not getattr(self, "_ready", False):
            QMessageBox.warning(self, "입력 확인 필요", "입력 검증에서 실패한 항목을 먼저 해결하세요.")
            return
        self._last_out_dir = out_dir
        for key, row in self.module_rows.items():
            row.set_status("waiting", "")
        selected = self.selected_parsers()
        if selected is not None:
            for pid, row in self.module_rows.items():
                if pid in self.parser_checks and pid not in selected:
                    row.set_status("skipped", "선택되지 않음")
        self.log_view.clear()
        self.btn_show_results.setEnabled(False)
        self.btn_cancel.setEnabled(True)
        self.stack.setCurrentIndex(2)
        self.btn_back.setVisible(True)
        try:
            self.runner.start(image, out_dir, selected, self.cb_quick.isChecked())
        except (RuntimeError, OSError) as exc:
            QMessageBox.critical(self, "실행 실패", str(exc))
            self.btn_cancel.setEnabled(False)
        self._update_run_button()

    @pyqtSlot(str)
    def _append_log(self, line):
        self.log_view.appendPlainText(line)

    @pyqtSlot(str)
    def _on_stage(self, text):
        self.lbl_stage.setText(text)

    @pyqtSlot(str, str)
    def _on_parser_status(self, name, status):
        row = self.module_rows.get(name)
        if row is not None:
            row.set_status(status)

    @pyqtSlot(str)
    def _on_evidence_info(self, body):
        self.module_rows["evidence"].set_status("success", "")
        self.log_view.appendPlainText("")
        self._evidence_line = body

    @pyqtSlot(int, str)
    def _on_finished(self, code, result_dir):
        self.btn_cancel.setEnabled(False)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        for key, row in self.module_rows.items():
            if row.badge.text() == "진행":
                row.set_status("failed", "실행 중 종료")
        self._update_run_button()
        if not result_dir:
            candidates = find_result_dirs(self._last_out_dir) if self._last_out_dir else []
            result_dir = candidates[-1] if candidates else ""
        if not result_dir:
            QMessageBox.critical(self, "분석 실패",
                                 "결과 폴더를 만들지 못했습니다 (exit=%d · %s).\n로그를 확인하세요."
                                 % (code, EXIT_MEANING.get(code, "알 수 없는 종료코드")))
            return
        if not self.case.is_empty():
            try:
                self.case.save(result_dir)
                self._append_log("[GUI] 사건 정보 저장: %s" % os.path.join(result_dir, "case_info.json"))
            except OSError as exc:
                self._append_log("[GUI] 사건 정보 저장 실패: %s" % exc)
        try:
            self._load_bundle(result_dir)
        except ResultLoadError as exc:
            QMessageBox.critical(self, "결과 읽기 실패", str(exc))
            return
        self.btn_show_results.setEnabled(True)
        self.stack.setCurrentIndex(3)
        if code != 0:
            QMessageBox.warning(self, "일부 단계 실패",
                                "exit=%d (%s)\nErrors & Limitations 탭에서 상세를 확인하세요."
                                % (code, EXIT_MEANING.get(code, "알 수 없는 종료코드")))

    # ------------------------------------------------------- 기존 결과 불러오기
    def _load_existing(self):
        path = QFileDialog.getExistingDirectory(self, "기존 결과 폴더 선택", "")
        if not path:
            return
        candidates = find_result_dirs(path)
        if not candidates:
            QMessageBox.warning(self, "결과 없음",
                                "선택한 폴더와 그 하위에서 %s / %s 를 찾지 못했습니다." % (REPORT_JSON, TIMELINE_CSV))
            return
        try:
            self._load_bundle(candidates[0])
        except ResultLoadError as exc:
            QMessageBox.critical(self, "결과 읽기 실패", str(exc))
            return
        if len(candidates) > 1:
            self._append_log("[GUI] 결과 폴더 %d개 중 첫 번째를 열었습니다: %s" % (len(candidates), candidates[0]))
        self.stack.setCurrentIndex(3)
        self.btn_back.setVisible(True)
        self._update_run_button()

    # ------------------------------------------------------------- 결과 표시
    def _load_bundle(self, result_dir):
        self.bundle = ResultBundle.load(result_dir)
        saved_case = CaseInfo.load(result_dir)
        if saved_case is not None and self.case.is_empty():
            self.case = saved_case
        self.search_box.setEnabled(True)
        self._fill_left_panel()
        self._fill_overview()
        self._fill_timeline()
        self._fill_conversations()
        self._fill_artifacts()
        self._fill_errors()
        states = self.bundle.parser_states()
        services = sum(1 for _n, _s, tl, cv in states if tl or cv)
        self.result_badge.setText("%d Parsers · %d with Results" % (len(states), services))

    def _fill_left_panel(self):
        case = self.case
        self.lbl_case.setText("<b>%s</b><br>%s<br>%s" % (
            case.case_name or "(사건명 없음)", case.case_number or "(사건번호 없음)",
            case.examiner or "(분석가 없음)"))
        evidence = self.bundle.evidence()
        self.lbl_evidence.setText("%s\n%s\nkind=%s · segments=%d" % (
            os.path.basename(evidence.get("path", "") or "-"), evidence.get("path", "-"),
            evidence.get("kind", "-"), len(evidence.get("segments", []) or [])))
        _clear_layout(self.services_box)
        for name, shown, _status, tl_rows, cv_rows in self.bundle.display_parser_states():
            self.services_box.addWidget(StatusRow(name, shown, "%d / %d" % (tl_rows, cv_rows)))
        _clear_layout(self.steps_box)
        report = self.bundle.report or {}
        done = bool(report.get("parsers"))
        merged = report.get("merged_output") or {}
        for name, ok in (("수집 (Evidence)", bool(report.get("evidence"))),
                         ("파싱 (Parsers)", done),
                         ("정규화 (Common Schema)", bool(merged)),
                         ("결과 생성 (Merged CSV · DB)", bool(merged) and self.bundle.has_db())):
            self.steps_box.addWidget(StatusRow(name, "success" if ok else "-"))

    def _fill_overview(self):
        notice = self.bundle.limitation_notice()        # 실제 warning 2종이 함께 있을 때만 값이 있다
        self.overview_notice.setText(notice or "")
        self.overview_notice.setVisible(bool(notice))
        _clear_grid(self.metrics_grid)
        for index, (label, value) in enumerate(self.bundle.metrics().items()):
            self.metrics_grid.addWidget(metric_card(label, value), index // 4, index % 4)
        rows = self.bundle.timeline_rows
        recent = [r for r in rows if cell(r, "Timestamp") != EMPTY][-5:]
        confirmed = [r for r in rows if cell(r, "Verdict") == VERDICT_CONFIRMED][:5]
        suspected = [r for r in rows if cell(r, "Verdict") == VERDICT_SUSPECTED][:5]
        html = [_STYLE, "<h3>Main Findings</h3>",
                "<p class='muted'>통합 Runner 는 별도 Finding 을 생성하지 않습니다. "
                "아래는 timeline.csv 행을 그대로 추린 요약입니다.</p>"]
        for title, subset in (("최근 Event", list(reversed(recent))), ("확정 Event", confirmed),
                              ("의심 Event", suspected)):
            html.append("<h4>%s</h4>" % title)
            if not subset:
                html.append("<p class='muted'>해당 행이 없습니다.</p>")
                continue
            html.append("<ul>")
            for row in subset:
                html.append("<li><code>%s</code> · %s · <b>%s</b> <span class='muted'>(%s)</span></li>" % (
                    _esc(cell(row, "Timestamp")), _esc(cell(row, "User_behavior")),
                    _esc(cell(row, "Verdict")), _esc(cell(row, "source_parser"))))
            html.append("</ul>")
        self.overview_notes.setHtml("".join(html))

    def _fill_timeline(self):
        columns = [c for c in TIMELINE_VIEW_COLUMNS if c in self.bundle.timeline_columns] or \
                  self.bundle.timeline_columns
        self.timeline_model = fill_model(columns, self.bundle.timeline_rows)
        self.timeline_proxy.setSourceModel(self.timeline_model)
        self.timeline_view.setModel(self.timeline_proxy)
        self.timeline_view.selectionModel().selectionChanged.connect(self._on_timeline_selected)
        empty = not self.bundle.timeline_rows
        self.timeline_empty.setText(self.bundle.empty_state_message("timeline") if empty else "")
        self.timeline_empty.setVisible(empty)
        header = self.timeline_view.horizontalHeader()
        for index, column in enumerate(columns):
            mode = QHeaderView.ResizeMode.Stretch if column in ("Behavior_details ", "Artifact_path") \
                else QHeaderView.ResizeMode.ResizeToContents
            header.setSectionResizeMode(index, mode)

    def _fill_conversations(self):
        self.session_list.clear()
        self.sessions = self.bundle.conversation_sessions()
        for session in self.sessions:
            item = QListWidgetItem("%s\n%s · %s" % (
                session.title if session.title != EMPTY else "(제목 없음)",
                session.model, session.first_timestamp))
            item.setData(Qt.ItemDataRole.UserRole, session)
            self.session_list.addItem(item)
        if self.sessions:
            self.session_list.setCurrentRow(0)
        else:
            lines = self.bundle.empty_state_message("conversations").splitlines()
            self.message_view.setHtml(_STYLE + "".join(
                "<p%s>%s</p>" % ("" if i == 0 else " class='muted'", _esc(line))
                for i, line in enumerate(lines)))

    def _fill_artifacts(self):
        rows = self.bundle.artifact_rows()
        columns = ["Artifact Type", "Service", "Model", "Artifact Path", "Related Behavior",
                   "First Timestamp", "Events"]
        model = fill_model(columns, rows, display=False)
        self.artifact_proxy.setSourceModel(model)
        self.artifact_view.setModel(self.artifact_proxy)
        self.artifact_view.selectionModel().selectionChanged.connect(self._on_artifact_selected)

    def _fill_errors(self):
        rows = self.bundle.error_rows()
        columns = ["Module", "Severity", "Type", "Message", "Processing Result"]
        model = fill_model(columns, rows, display=False)
        self.error_proxy.setSourceModel(model)
        self.error_view.setModel(self.error_proxy)
        self.error_view.selectionModel().selectionChanged.connect(self._on_error_selected)
        notes = self.bundle.limitations()
        html = [_STYLE, "<ul>"] + ["<li>%s</li>" % _esc(n) for n in notes] + ["</ul>"]
        if not notes:
            html = [_STYLE, "<p class='muted'>보고서에 기록된 제한 사항이 없습니다.</p>"]
        self.limitations_view.setHtml("".join(html))

    # ----------------------------------------------------------- 선택 → 상세
    def _selected_row(self, view):
        indexes = view.selectionModel().selectedRows() if view.selectionModel() else []
        if not indexes:
            return None
        return indexes[0].data(Qt.ItemDataRole.UserRole)

    def _on_timeline_selected(self, *_args):
        row = self._selected_row(self.timeline_view)
        if row is None:
            return
        verdict = cell(row, "Verdict")
        self._set_badge(verdict, VERDICT_BADGE.get(verdict, "BadgeNeutral"))
        sections = [("행위", cell(row, "User_behavior")), ("Timestamp", cell(row, "Timestamp")),
                    ("Behavior Details", cell(row, "Behavior_details ")),
                    ("Model", cell(row, "Model")), ("Source Parser", cell(row, "source_parser"))]
        paths = [("Artifact Path", cell(row, "Artifact_path")),
                 ("Artifact Path (normalized)", cell(row, "artifact_path_normalized")),
                 ("Artifact Details", cell(row, "Artifact_details "))]
        meta = [(DISPLAY_NAMES.get(k, k), cell(row, k)) for k in
                ("volume_ref", "parser_version", "source_file", "parse_time_utc", "evidence_id")
                if k in self.bundle.timeline_columns]
        self._set_detail(_detail_html(cell(row, "User_behavior"), sections, paths, meta))
        self._set_artifact_path(cell(row, "Artifact_path"))

    def _on_artifact_selected(self, *_args):
        row = self._selected_row(self.artifact_view)
        if row is None:
            return
        self._set_badge("Artifact", "BadgeTeal")
        sections = [("Artifact Type", row.get("Artifact Type", EMPTY)),
                    ("Service", row.get("Service", EMPTY)), ("Model", row.get("Model", EMPTY)),
                    ("Related Behavior", row.get("Related Behavior", EMPTY)),
                    ("First Timestamp", row.get("First Timestamp", EMPTY)),
                    ("Events", row.get("Events", EMPTY))]
        self._set_detail(_detail_html(row.get("Artifact Path", EMPTY), sections,
                                      [("Artifact Path", row.get("Artifact Path", EMPTY))], []))
        self._set_artifact_path(row.get("Artifact Path", EMPTY))

    def _on_error_selected(self, *_args):
        row = self._selected_row(self.error_view)
        if row is None:
            return
        severity = row.get("Severity", "-")
        self._set_badge(STATUS_BADGE.get(severity, ("오류", "BadgeRed"))[0],
                        STATUS_BADGE.get(severity, ("오류", "BadgeRed"))[1])
        raw = row.get("_raw") or {}
        sections = [("Module", row.get("Module", EMPTY)), ("Severity", severity),
                    ("Type", row.get("Type", EMPTY)),
                    ("Processing Result", row.get("Processing Result", EMPTY))]
        paths = [("Message", row.get("Message", EMPTY))]
        meta = [(k, str(v)) for k, v in raw.items() if k != "message" and v is not None]
        self._set_detail(_detail_html(row.get("Type", EMPTY), sections, paths, meta))
        run_log = raw.get("run_log") or ""
        self._set_artifact_path(run_log if run_log else EMPTY)

    def _on_session_changed(self, index):
        if index < 0 or index >= len(getattr(self, "sessions", [])):
            return
        session = self.sessions[index]
        html = [_STYLE, "<h3>%s</h3>" % _esc(session.title if session.title != EMPTY else "(제목 없음)"),
                "<p class='muted'>conversation_uuid: <code>%s</code> · %s · 메시지 %d건</p>"
                % (_esc(session.conversation_uuid), _esc(session.model), len(session.messages))]
        for message in session.messages:
            role = cell(message, "role")
            html.append(
                "<div class='msg'><div class='role'>%s <span class='muted'>· %s · order %s</span></div>"
                "<div class='content'>%s</div>"
                "<div class='meta muted'>message_uuid %s<br>parent %s<br>artifact %s</div></div>"
                % (_esc(role.upper()), _esc(cell(message, "timestamp")), _esc(cell(message, "message order")),
                   _esc(cell(message, "content")).replace("\n", "<br>"),
                   _esc(cell(message, "message_uuid")), _esc(cell(message, "parent_message_uuid")),
                   _esc(cell(message, "Artifact_path"))))
        self.message_view.setHtml("".join(html))

    def _set_badge(self, text, kind):
        self.detail_badge.setText(text or "-")
        self.detail_badge.setObjectName(kind)
        self.detail_badge.style().unpolish(self.detail_badge)
        self.detail_badge.style().polish(self.detail_badge)

    def _set_detail(self, html):
        self.detail_view.setHtml(_STYLE + html if not html.startswith(_STYLE) else html)

    def _set_artifact_path(self, path):
        """실제로 존재하는 경로일 때만 '근거 파일 위치 열기' 를 활성화한다."""
        self._detail_path = path if path and path != EMPTY else ""
        exists = bool(self._detail_path) and os.path.exists(self._detail_path)
        self.btn_open_artifact.setEnabled(exists)
        self.btn_open_artifact.setToolTip("" if exists else
                                          "이미지 내부 경로이거나 이 PC에 존재하지 않아 열 수 없습니다")

    # ------------------------------------------------------------------ 기타
    def _on_search(self, text):
        if self.bundle is None:                              # 결과를 아직 읽지 않았으면 필터할 것이 없다
            return
        for proxy in (self.timeline_proxy, self.artifact_proxy, self.error_proxy):
            if proxy.sourceModel() is not None:
                proxy.set_needle(text)
        needle = (text or "").strip().lower()
        for index in range(self.session_list.count()):
            item = self.session_list.item(index)
            session = item.data(Qt.ItemDataRole.UserRole)
            hay = " ".join([session.title, session.conversation_uuid, session.model] +
                           [cell(m, "content") + cell(m, "role") for m in session.messages]).lower()
            item.setHidden(bool(needle) and needle not in hay)

    def _open_result_dir(self):
        if self.bundle is None or not open_in_explorer(self.bundle.result_dir):
            QMessageBox.information(self, "결과 폴더", "열 수 있는 결과 폴더가 없습니다.")

    def _open_artifact_path(self):
        if self._detail_path and not open_in_explorer(self._detail_path):
            QMessageBox.information(self, "경로 열기", "이 경로는 이 PC에서 열 수 없습니다.")

    def closeEvent(self, event):
        if self.runner.is_running():
            answer = QMessageBox.question(self, "분석 진행 중", "분석을 중단하고 종료하시겠습니까?")
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.runner.cancel()
        event.accept()


# ----------------------------------------------------------------- HTML 조각
_STYLE = """<style>
body { font-family: "Segoe UI", "Malgun Gothic", sans-serif; font-size: 10pt; color: #17202a; }
h3 { font-size: 11pt; margin: 2px 0 6px 0; }
h4 { font-size: 9.5pt; color: #1c5f70; margin: 10px 0 3px 0; }
.muted { color: #667381; font-size: 9pt; }
code, .path { font-family: "Cascadia Mono", "Consolas", monospace; font-size: 9pt;
              word-break: break-all; }
.sec { border-top: 1px solid #d9dee5; padding-top: 7px; margin-top: 7px; }
.key { color: #667381; font-size: 8.5pt; font-weight: 600; }
.msg { border: 1px solid #d9dee5; border-radius: 3px; padding: 7px 9px; margin-bottom: 7px;
       background: #ffffff; }
.role { font-weight: 600; color: #1c5f70; font-size: 9pt; margin-bottom: 3px; }
.content { white-space: pre-wrap; }
.meta { margin-top: 5px; font-family: "Cascadia Mono", "Consolas", monospace; font-size: 8pt;
        word-break: break-all; }
ul { margin: 2px 0 2px 16px; padding: 0; }
li { margin-bottom: 3px; }
</style>"""


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _detail_html(heading, sections, paths, meta):
    html = ["<h3>%s</h3>" % _esc(heading or "-")]
    for key, value in sections:
        html.append("<div class='sec'><div class='key'>%s</div><div>%s</div></div>"
                    % (_esc(key), _esc(value).replace("\n", "<br>")))
    for key, value in paths:
        html.append("<div class='sec'><div class='key'>%s</div><div class='path'>%s</div></div>"
                    % (_esc(key), _esc(value)))
    if meta:
        html.append("<div class='sec'><div class='key'>관련 Metadata</div>")
        for key, value in meta:
            html.append("<div class='path'>%s = %s</div>" % (_esc(key), _esc(value)))
        html.append("</div>")
    return "".join(html)


def _clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()


def _clear_grid(grid):
    _clear_layout(grid)
