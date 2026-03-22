from TicTacToePlayer import TicTacToePlayer
from WinnerChecker import WinnerChecker
from TicTacToeChars import TicTacToeChars
from enum import Enum
from Cell import Cell
from Field import Field

class GameStates(Enum):
    ONGOING = 0,
    HAS_WINNER = 1,
    DRAW = 2,
    NOT_STARTED = 3

class TicTacToeGame:
    def __init__(self, field: Field, winner_checker: WinnerChecker):
        self.field = field
        self.players: list[TicTacToePlayer] = []
        self.empty_chars_count = field.length * field.width
        self.winner_checker = winner_checker
        self.game_state = GameStates.NOT_STARTED
        self.is_game_over = False
        self.winning_line: list[Cell[TicTacToeChars]] | None = None

    def start(self):
        if len(self.players) < 2:
            raise ValueError("Not enough players")
        self.game_state = GameStates.ONGOING

    def restart(self):
        for i in range(self.field.length):
            for j in range(self.field.width):
                self.field.set_cell(i, j, TicTacToeChars.EMPTY)
        self.empty_chars_count = self.field.length * self.field.width
        self.game_state = GameStates.ONGOING
        self.is_game_over = False
        self.winning_line = None
        for player in self.players:
            player.clear_moves()

    def get_game_state(self) -> GameStates:
        return self.game_state

    def get_winning_line(self) -> list[Cell[TicTacToeChars]]:
        if self.game_state != GameStates.HAS_WINNER:
            raise ValueError("There is no winner")
        return self.winning_line  # type: ignore

    def get_is_game_over(self) -> bool:
        return self.is_game_over

    def add_player(self, player: TicTacToePlayer):
        if self.game_state != GameStates.NOT_STARTED:
            raise ValueError("Game has already started")
        self.players.append(player)

    def make_move_by_player(self, cell: Cell[TicTacToeChars], player_making_move: TicTacToePlayer):
        if self.game_state == GameStates.NOT_STARTED:
            raise ValueError("Game has not started yet")
        row = cell.get_row()
        column = cell.get_column()

        if self.is_game_over:
            raise ValueError("Game is over")
        
        current_player = self.players[0]

        if player_making_move != current_player:
            raise ValueError("It's not your turn")
        if self.field.get_value(row, column) != TicTacToeChars.EMPTY:
            raise ValueError("Cell is not empty")

        self.field.set_cell(row, column, player_making_move.get_char())
        current_player.save_move(cell)
        self.empty_chars_count -= 1
        self.define_game_result(current_player)
        self.is_game_over = self.game_state == GameStates.HAS_WINNER or self.game_state == GameStates.DRAW
        if not self.is_game_over:
            self._switch_player()

    def define_game_result(self, current_player: TicTacToePlayer):
        result = self.winner_checker.check_winner(self.field, current_player.moves)
        if result['is_win']:
            self.game_state = GameStates.HAS_WINNER
            self.winning_line = result['winning_line']
        elif self.check_draw():
            self.game_state = GameStates.DRAW

    def get_winner(self) -> TicTacToePlayer:
        if self.game_state != GameStates.HAS_WINNER:
            raise ValueError("There is no winner")
        return self.players[0]

    def _switch_player(self):
        current_player = self.players.pop(0)
        if current_player is not None:
            self.players.append(current_player)
        else:
            raise ValueError("Player cannot be undefined")

    def check_draw(self) -> bool:
        return self.empty_chars_count == 0