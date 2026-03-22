from TicTacToeChars import TicTacToeChars
from Cell import Cell

class TicTacToePlayer:
    def __init__(self, char: TicTacToeChars, game: "TicTacToeGame", name: str): # type: ignore
        self.char = char
        self.game = game
        self.name = name
        self.moves: set[Cell[TicTacToeChars]] = set()
        game.add_player(self)

    def make_move(self, row, column):
        cell = self.game.field.get_cell(row, column)
        self.game.make_move_by_player(cell, self)

    def save_move(self, move: Cell[TicTacToeChars]):
        self.moves.add(move)

    def get_moves(self) -> set[Cell[TicTacToeChars]]:
        return set(self.moves)
    
    def get_char(self) -> TicTacToeChars:
        return self.char
    
    def clear_moves(self):
        self.moves.clear()