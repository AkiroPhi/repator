"""Modules that create the combox box history in order to delete some entries"""

# coding=utf-8

from PyQt5.QtWidgets import (QComboBox, QTreeView, QAbstractItemView, QHeaderView)
from PyQt5.QtGui import (QStandardItemModel, QStandardItem)

class History(QComboBox):
    """
    Class that represent the history of some fields and allow to delete some entries.
    """

    def __init__(self, parent):
        super().__init__(parent)
        self._parent = parent
        self.init_view()

    def init_model(self):
        """
        Init the model attached to the history.
        """
        self.setModel(QStandardItemModel())

    def init_view(self):
        """
        Init the view attached to the history.
        """
        self.init_model()
        view = QTreeView()
        view.setHeaderHidden(True)
        view.setSelectionBehavior(QAbstractItemView.SelectItems)
        view.setModel(self.model())
        view.pressed.connect(self.dealWithPressEvent)
        view.header().setStretchLastSection(False)
        self.setView(view)

    def addItem(self, txt_item):
        """
        Add item to the model and the view and add a delete fields if needed.
        """
        choice = QStandardItem(txt_item)
        self.model().appendRow([choice, QStandardItem("delete") ]
                               if self.model().rowCount() > 0 else choice)
        if self.view().header().count() > 1:
            self.view().header().setSectionResizeMode(0, QHeaderView.Stretch)


    def removeItem(self, row):
        """
        Remove item at row in the model and the database.
        """
        database = self._parent.database
        history_field_name = self.accessibleName()
        field_tab = history_field_name.split('-')
        field_name = history_field_name.replace("History", "")
        history = database.search_by_id(int(field_tab[1]))[field_tab[0]]
        history.pop(row)
        database.update(int(field_tab[1]), field_tab[0], history)

    def dealWithPressEvent(self, index):
        """
        Event called each time that the user select a fields in the view.
        """
        item = self.model().itemFromIndex(index)
        col, row = item.column(), item.row()
        if col == 1 and row > 0: # don't delete the first row
            self.removeItem(row)
        # else nothing to do
