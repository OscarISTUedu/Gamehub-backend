from TicTacToePlayer import TicTacToePlayer
from Field import Field
from TicTacToeBestMoveFinder import TicTacToeBestMoveFinder

class TicTacToeBot:
    def __init__(self, player: TicTacToePlayer, best_move_finder: TicTacToeBestMoveFinder, field: Field, opponent: TicTacToePlayer):
        self.player = player
        self.best_move_finder = best_move_finder
        self.field = field
        self.opponent = opponent

    def make_move(self) -> dict[str, int]:
        best_move = self.best_move_finder.find_best_move(self.field, self.player.get_moves(), self.opponent.get_moves(), self.opponent.get_char())
        self.player.make_move(best_move["row"], best_move["column"])