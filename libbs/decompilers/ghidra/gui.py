import sys
from pathlib import Path
import subprocess

from libbs.ui.version import set_ui_version
set_ui_version("PySide6")
from libbs.ui.qt_objects import (
    QApplication, QWidget, QLabel, QMainWindow, QVBoxLayout, QPushButton, QFileDialog, QGridLayout, QDialog
)


class FileSelectorDialog(QDialog):
    def __init__(self):
        super(FileSelectorDialog, self).__init__()
        self.setWindowTitle("Run a LibBS Python script")

        self._init_widgets()

    #
    # Private methods
    #

    def _init_widgets(self):
        self._layout = QGridLayout()
        row = 0

        # make a button to open a dialog that selects a file
        self._button = QPushButton("File Path")
        self._button.clicked.connect(self._select_file)
        self._layout.addWidget(self._button, row, 0)

        # make a label to show the selected file
        self._label = QLabel()
        self._layout.addWidget(self._label, row, 1)
        row += 1

        # make a run and cancel button
        self._run_button = QPushButton("Run")
        self._run_button.clicked.connect(self._run)
        self._layout.addWidget(self._run_button, row, 0)

        self._cancel_button = QPushButton("Cancel")
        self._cancel_button.clicked.connect(self._cancel)
        self._layout.addWidget(self._cancel_button, row, 1)

        self.setLayout(self._layout)

    def _select_file(self):
        # open a dialog to select a file
        file_name, _ = QFileDialog.getOpenFileName(self, "Select a LibBS Python script")

        # update the label to show the selected file
        self._label.setText(file_name)

    def _run(self):
        file_path = self._label.text()
        if not file_path:
            return

        file_path = Path(file_path).absolute()
        if not file_path.exists():
            return

        subprocess.Popen(f"python3 {file_path}".split(" "))
        self.close()

    def _cancel(self):
        self.close()

    def closeEvent(self, event):
        sys.exit(0)


def start_file_selector_ui():
    app = QApplication()
    file_selector = FileSelectorDialog()
    file_selector.show()
    file_selector.exec_()
    app.exec_()

