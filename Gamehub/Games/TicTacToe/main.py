from TicTacToe import TicTacToeGame, GameStates
from TicTacToePlayer import TicTacToePlayer
from Field import Field
from WinnerChecker import WinnerChecker
from TicTacToeChars import TicTacToeChars
from TicTacToeBestMoveFinder import TicTacToeBestMoveFinder
from TicTacToeBot import TicTacToeBot

field = Field(3, 3)

winnerChecker = WinnerChecker(3)

game = TicTacToeGame(field, winnerChecker)

player1 = TicTacToePlayer(TicTacToeChars.CROSS, game, 'Player 1')
player2 = TicTacToePlayer(TicTacToeChars.CIRCLE, game, 'Player 2')

best_move_finder = TicTacToeBestMoveFinder(TicTacToeChars.CIRCLE, winnerChecker, player1)

bot = TicTacToeBot(player2, best_move_finder, field, player1)

game.start()

player1.make_move(0, 0)
bot.make_move()
player1.make_move(1, 0)
bot.make_move()
player1.make_move(2, 2)
bot.make_move()


print(game.get_game_state())

for i in range(field.length):
    for j in range(field.width):
        print(field.get_value(i, j), end=' ')
    print()