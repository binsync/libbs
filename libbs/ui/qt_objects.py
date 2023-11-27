from libbs.ui.version import ui_version

if ui_version == "PySide6":
    from PySide6.QtCore import (
        QDir, Qt, Signal, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QPersistentModelIndex,
        QEvent, QThread, Slot, QObject, QPropertyAnimation, QAbstractAnimation, QParallelAnimationGroup
    )
    from PySide6.QtWidgets import (
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMenu,
        QMessageBox,
        QPushButton,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
        QDialogButtonBox,
        QTableView,
        QFontDialog,
        QCheckBox,
        QMainWindow,
        QApplication,
        QFrame,
        QWidget,
        QSizePolicy,
        QScrollArea,
        QToolButton,
        QProgressBar
    )
    from PySide6.QtGui import (
        QFontDatabase,
        QColor,
        QKeyEvent,
        QFocusEvent,
        QIntValidator,
        QAction,
        QImage,
    )
else:
    from PyQt5.QtCore import (
        QDir, Qt, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QPersistentModelIndex,
        QEvent, QThread, QObject, QPropertyAnimation, QAbstractAnimation, QParallelAnimationGroup
    )
    from PyQt5.QtCore import pyqtSignal as Signal
    from PyQt5.QtCore import pyqtSlot as Slot
    from PyQt5.QtWidgets import (
        QAbstractItemView,
        QCheckBox,
        QComboBox,
        QDialog,
        QFileDialog,
        QGridLayout,
        QGroupBox,
        QHBoxLayout,
        QHeaderView,
        QLabel,
        QLineEdit,
        QMenu,
        QMessageBox,
        QPushButton,
        QStatusBar,
        QTableWidget,
        QTableWidgetItem,
        QTabWidget,
        QVBoxLayout,
        QWidget,
        QDialogButtonBox,
        QTableView,
        QAction,
        QFontDialog,
        QCheckBox,
        QMainWindow,
        QApplication,
        QFrame,
        QWidget,
        QSizePolicy,
        QScrollArea,
        QToolButton,
        QProgressBar,
    )
    from PyQt5.QtGui import (
        QFontDatabase,
        QColor,
        QKeyEvent,
        QFocusEvent,
        QIntValidator,
        QImage
    )
