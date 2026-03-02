from Cell import Cell
from TicTacToeChars import TicTacToeChars

class Field:
    def __init__(self, rows, columns):
        self.field = self.create_empty_field(rows, columns)
        field = self.field
        self.length = len(field)
        self.width = len(field[0]) if field else 0

    def get_cell(self, row: int, column: int) -> Cell[TicTacToeChars]:
        return self.field[row][column]

    def get_value(self, row: int, column: int) -> TicTacToeChars:
        return self.field[row][column].value

    def set_cell(self, row: int, column: int, value: TicTacToeChars):
        self.field[row][column].value = value

    def create_empty_field(self, rows, columns) -> list[list[Cell[TicTacToeChars]]]:
        result: list[list[Cell[TicTacToeChars]]]  = []
        for i in range(rows):
            result.append([])
            for j in range(columns):
                result[i].append(Cell(i, j, TicTacToeChars.EMPTY))
        return result


    def get_field_copy(self) -> 'Field':
        new_field = [[Cell(cell.get_row(), cell.get_column(), cell.value) for cell in row] for row in self.field]
        return Field(new_field)