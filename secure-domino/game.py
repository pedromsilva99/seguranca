from deck_utils import Deck, Player


class Game:
    def __init__(self, max_players):
        self.deck = Deck()
        print("Deck created \n", self.deck)
        self.max_players = max_players
        self.nplayers = 0
        self.players = []
        self.player_index = 0
        self.init_distribution = True
        self.next_action = "get_piece"
        self.started = False
        self.all_ready_to_play = False
        self.scores = []
        self.encr = []

    def checkDeadLock(self):
        return all([player.nopiece for player in self.players])

    def allPlayersWithPieces(self):
        return 28 - len(self.deck.deck) == 15

    def currentPlayer(self):
        return self.players[self.player_index]

    def nextPlayer(self):
        self.player_index += 1
        if self.player_index == self.max_players:
            self.player_index = 0
        return self.players[self.player_index]

    def previousPlayer(self):
        self.player_index -=1
        if self.player_index == 0:
            self.player_index = self.max_players
        return self.players[self.player_index]    

    def addPlayer(self, name, socket, pieces):
        self.nplayers += 1
        assert self.max_players >= self.nplayers
        player = Player(name, socket, pieces)
        print(player)
        self.players.append(player)

    def hasHost(self):
        return len(self.players) > 0

    def hasPlayer(self, name):
        for player in self.players:
            if name == player.name:
                return True
        return False

    def isFull(self):
        return self.nplayers == self.max_players

    def restartGame(self):
        self.init_distribution = True
        self.next_action = "get_piece"
        self.started = False
        self.all_ready_to_play = False
        for pl in self.players:
            pl.restartGame()
        while self.deck.in_table != []:
            piece = self.deck.in_table.pop(0)
            self.deck.deck.append(piece)
        #self.deck.in_table=[]
        # newDeck = Deck()
        # self.deck = newDeck


    def toJson(self):
        msg = {"next_player": self.players[self.player_index].name,
               "nplayers": self.nplayers, "next_action": self.next_action,
               "scores": self.scores}
        msg.update(self.deck.toJson())
        return msg
