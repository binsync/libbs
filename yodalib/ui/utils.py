import sys

from .qt_objects import (
    QDialog, QVBoxLayout, QProgressBar, QLabel, QPushButton, Qt, QThread, QApplication, Signal
)


class QProgressBarDialog(QDialog):
    def __init__(self, label_text="Loading...", on_cancel_callback=None, parent=None):
        super().__init__(parent)
        self.on_cancel_callback = on_cancel_callback

        self.setWindowTitle("YODA Loading...")
        self.setWindowModality(Qt.ApplicationModal)
        self.layout = QVBoxLayout()

        # Add the label
        self.layout.addWidget(QLabel(label_text))

        # Add the progress bar
        self.progressBar = QProgressBar(self)
        self.progressBar.setValue(0)
        self.layout.addWidget(self.progressBar)

        # Add cancel button on the bottom
        self.button = QPushButton("Cancel", self)
        self.button.clicked.connect(self.on_cancel_clicked)
        self.layout.addWidget(self.button)

        self.setLayout(self.layout)

        # Initialize progress value
        self.progress = 0

    def on_cancel_clicked(self):
        if self.on_cancel_callback is not None:
            self.on_cancel_callback()

        self.close()

    def on_finished(self):
        self.close()

    def update_progress(self, value):
        self.progress += value
        if self.progress >= 100:
            self.on_finished()

        self.progressBar.setValue(self.progress)
