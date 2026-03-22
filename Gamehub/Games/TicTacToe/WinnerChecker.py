from enum import Enum
from Cell import Cell
from Field import Field
from TicTacToeChars import TicTacToeChars

class WinnerChecker:
    def __init__(self, values_to_win: int):
        self.values_to_win = values_to_win

    def check_winner(self, field: Field, player_moves: set[Cell[TicTacToeChars]]) -> dict:
        if self.values_to_win <= 0 or self.values_to_win > max(field.length, field.width):
            raise ValueError("Values to win should be between 1 and field dimensions")

        directions = [(0, 1), (1, 0), (1, 1), (1, -1)]  # горизонталь, вертикаль, 2 диагонали

        for move in player_moves:
            row = move.get_row()
            column = move.get_column()

            for dr, dc in directions:
                win_line = [move]

                for i in range(1, self.values_to_win):
                    nr = row + i * dr
                    nc = column + i * dc
                    if not (0 <= nr < field.length and 0 <= nc < field.width):
                        break
                    cell = field.get_cell(nr, nc)
                    win_line.append(cell)
                    if cell not in player_moves:
                        break
                else:
                    # Цикл for прошёл полностью без break → нашли победу!
                    return {'is_win': True, 'winning_line': win_line}

        return {'is_win': False, 'winning_line': None}