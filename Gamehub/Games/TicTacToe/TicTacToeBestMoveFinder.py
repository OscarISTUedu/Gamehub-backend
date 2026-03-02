from enum import Enum
from Cell import Cell
from Field import Field
from TicTacToeChars import TicTacToeChars
from TicTacToePlayer import TicTacToePlayer
from WinnerChecker import WinnerChecker

class GameResults(Enum):
    WIN = 0
    LOSE = 1
    DRAW = 2

class TicTacToeBestMoveFinder:
    def __init__(self, value: TicTacToeChars, winner_checker: WinnerChecker, opponent: TicTacToePlayer):
        self.opponent = opponent
        self.value = value
        self.winner_checker = winner_checker
        self.scores = {
            GameResults.WIN: 10,
            GameResults.LOSE: -10,
            GameResults.DRAW: 0
        }

    def is_draw(self, field: Field) -> bool:
        for i in range(field.length):
            for j in range(field.width):
                if field.get_value(i, j) == TicTacToeChars.EMPTY:
                    return False
        return True

    def find_best_move(self, field: Field, moves, opponent_moves: set[Cell], opponent_value: TicTacToeChars) -> dict[str, int]:
        best_score = float('-inf')
        best_move = {'row': -1, 'column': -1}
        player = {'moves': set(opponent_moves), 'value': opponent_value}
        bot = {'moves': set(moves), 'value': self.value}
        empty_char = TicTacToeChars.EMPTY
        bot_moves = bot['moves']
        for i in range(field.length):
            for j in range(field.width):
                cell = field.get_cell(i, j)
                if cell.value != empty_char:
                    continue
                cell.value = self.value
                bot_moves.add(cell)
                score = self.minimax(field, 0, False, player, bot)
                cell.value = empty_char
                bot_moves.remove(cell)
                if score > best_score:
                    best_score = score
                    best_move = {'row': i, 'column': j}
        return best_move

    def minimax(self, field: Field, depth: int, is_maximizing: bool, opponent: dict, bot: dict) -> int:
        scores = self.scores
        winner_checker = self.winner_checker
        
        # Проверка победы того, кто только что сделал ход
        if not is_maximizing:
            if winner_checker.check_winner(field, bot['moves'])['is_win']:
                return scores[GameResults.WIN] - depth
        else:
            if winner_checker.check_winner(field, opponent['moves'])['is_win']:
                return scores[GameResults.LOSE] + depth
        
        if self.is_draw(field):
            return scores[GameResults.DRAW]
        
        best_score = float('-inf') if is_maximizing else float('inf')
        making_move = bot if is_maximizing else opponent
        
        for i in range(field.length):
            for j in range(field.width):
                cell = field.get_cell(i, j)
                if cell.value != TicTacToeChars.EMPTY:
                    continue
                
                cell.value = making_move['value']
                making_move['moves'].add(cell)
                
                score = self.minimax(field, depth + 1, not is_maximizing, opponent, bot)
                
                making_move['moves'].remove(cell)
                cell.value = TicTacToeChars.EMPTY
                
                if is_maximizing:
                    best_score = max(score, best_score)
                else:
                    best_score = min(score, best_score)
                    
        return best_score