"""Interface for files chooser."""

# coding=utf-8
import sys

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QWidget, QApplication, QPushButton, QFileDialog, QGridLayout, QLabel, \
    QComboBox, QScrollArea

from src.ui.rich_text_edit import RichTextEdit


class ImagesChooser(QWidget):
    creationImage = pyqtSignal(int, str, name="creationImage")
    deletionImage = pyqtSignal(int, name="deletionImage")
    modificationImage = pyqtSignal(int, str, str, name="modificationImage")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent = parent
        self.lst = {}
        self.row = 0
        self.index = 0
        self.init_tab()
        self.add_chooser()

    def init_tab(self):
        """Initializes features and widgets of a tab."""

        self.grid = QGridLayout()
        self.grid.setSpacing(5)
        self.grid.setContentsMargins(10, 5, 10, 5)
        self.grid.setAlignment(Qt.AlignTop)
        self.setLayout(self.grid)

    def add_chooser(self, filename=None, text=None, history=None):
        chooser = LineChooser(self, self.index, self.add_chooser, self.del_chooser)
        self.lst[self.index] = chooser
        self.grid.addWidget(chooser)
        self.index += 1
        self.row += 1

        # TODO: modifier la ligne quand les champs sont not None

        if filename is not None:
            print(filename)

        if text is not None:
            print(text)

        if history is not None:
            print(history)

    def del_chooser(self, index):
        self.grid.removeWidget(self.lst[index])
        self.lst[index].deleteLater()
        del self.lst[index]
        self.row -= 1
        self.repaint()
        if self.row == 0:
            self.add_chooser()
            self.row = 1

    def emit_creation(self, index, file):
        self.creationImage.emit(index, file)

    def emit_deletion(self, index):
        self.deletionImage.emit(index)

    def emit_modification(self, index, file, text):
        self.modificationImage.emit(index, file, text)


class LineChooser(QWidget):

    def __init__(self, parent, index, fct_add, fct_remove):
        super().__init__(parent)
        self.parent = parent
        self.fct_add = fct_add
        self.fct_remove = fct_remove
        self.dialog = QFileDialog()
        self.index = index
        self.file = ""
        self.extension = "*.png\n*.jpg\n*.pdf\n*.gif"

        self.button_add = QPushButton("Select a file")
        self.button_del = QPushButton("Delete file")
        self.history = QComboBox()
        self.label_file = QLabel("")
        self.label_text = RichTextEdit(args="", parent=self)

        self.init_tab()
        self.init_connection()

    def init_tab(self):
        """Initializes features and widgets of a tab."""

        self.label_text.setFixedHeight(150)
        self.enabled_line(False)

        scroll = QScrollArea()
        scroll.setFixedWidth(200)
        scroll.setFixedHeight(60)
        scroll.setWidget(self.label_file)
        scroll.setWidgetResizable(True)

        self.grid = QGridLayout()
        self.grid.setSpacing(5)
        self.grid.setContentsMargins(10, 5, 10, 5)
        self.grid.setAlignment(Qt.AlignTop)
        self.setLayout(self.grid)

        self.grid.addWidget(self.button_add, 0, 0)
        self.grid.addWidget(self.history, 0, 1)
        self.grid.addWidget(scroll, 1, 0)
        self.grid.addWidget(self.label_text, 1, 1, 2, 1)
        self.grid.addWidget(self.button_del, 2, 0)

    def init_connection(self):
        """Initializes connections of widgets."""

        self.button_add.clicked.connect(self.select_file)
        self.button_del.clicked.connect(self.delete_line)
        self.label_text.text_changed.connect(lambda:
                                             self.parent.emit_modification(self.index, self.file,
                                                                           self.label_text.to_plain_text()))

    def select_file(self):
        file_name, _ = self.dialog.getOpenFileName(filter=self.extension)
        if file_name:
            if not self.extension_is_correct(file_name):
                return
            is_created = len(self.file) == 0
            self.file = file_name
            if len(self.label_file.text()) == 0:
                self.fct_add()
            self.label_file.setText(self.file)
            self.enabled_line(True)
            try:
                if is_created:
                    self.parent.emit_creation(self.index, self.file)
                else:
                    self.parent.emit_modification(self.index, self.file, self.label_text.to_plain_text())
            except:
                pass

    def extension_is_correct(self, string):
        if not isinstance(string, str):
            return False
        for ext in self.extension.split("\n"):
            _, name = ext.split(".")
            if string.endswith(name):
                return True
        return False

    def delete_line(self):
        self.parent.emit_deletion(self.index)
        self.fct_remove(self.index)

    def enabled_line(self, value):
        self.label_text.setEnabled(value)
        self.history.setEnabled(value)
        self.button_del.setEnabled(value)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ImagesChooser()
    window.show()
    sys.exit(app.exec_())
