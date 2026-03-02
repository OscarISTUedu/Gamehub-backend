from typing import TypeVar

T = TypeVar('T')

class Cell:
    def __init__(self, row: int, column: int, value: T):
        self.row = row
        self.column = column
        self.value = value

    def get_row(self) -> int:
        return self.row

    def get_column(self) -> int:
        return self.column