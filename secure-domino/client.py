import socket
import sys
import pickle
import Colors
import string
from deck_utils import Player
import random
from Crypto.Cipher import AES

secret=''

class client():
    # Returns string without 16 bytes padding
    def removePaddingStr (self,msg):
        s=""
        for i in range(0,len(msg)):
            if (msg[i]!=0):
                s=s+chr (msg[i])
        return s

    # Creates a bytes with 16 bytes padding
    def pad16Bytes (self,msg):
        paddingChars=16-len(msg)%16
        paddedMsg=msg
        for i in range(paddingChars):
            paddedMsg=paddedMsg+b'\0'
        return paddedMsg

    # Creates a string with 16 bytes padding
    def pad16Str (self,msg):
        paddingChars=16-len(str (msg))%16
        paddedMsg=''.join(['\0' for i in range(paddingChars)])
        return str (msg)+paddedMsg

    # Send manager message
    def sendData(self,msg):
        global secret
        # encrypton with AES and the message needs to be a multiple of 16
        iv = 16 * b'\0'
        aes = AES.new(secret, AES.MODE_CBC, iv)
        encd = aes.encrypt(self.pad16Bytes(msg))
        try:
            self.sock.send(encd)
            return True
        except:
            return False

    def __init__(self, host, port):
        global secret
        print('\n--------------------------------------------------------')
        print("Connecting with the server ...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.connect((host, port))
        # negotiate keys with Diffie-Hellman algorithm
        g = 9
        p = 1001 
        random.seed()
        a = random.randint(10000, 999999)
        A = (g**a) % p
        self.sock.send(bytes(str(A), 'utf-8'))
        keyServer = self.sock.recv(4096).decode("utf-8")
        secretClient = (int(keyServer)**a) % p
        print('Shared secret: %s' % secretClient)

        # secret needs to have 16 characters
        secret=bytes (self.pad16Str(str (secretClient)),'utf-8')

        # recieve communication status from manager
        comStatus=self.sock.recv(4096)
        iv = 16 * b'\0'
        aes = AES.new(secret, AES.MODE_CBC, iv)
        data = aes.decrypt(comStatus)
        data=self.removePaddingStr(data)
        print ('Status of manager: %s' % data)

        # if manager responds with "Online", the client send "OK"
        if (data == "Online"):
            iv = 16 * b'\0'
            aes = AES.new(secret, AES.MODE_CBC, iv)
            data1=aes.encrypt(bytes (self.pad16Str("OK"),'utf-8'))
            self.sock.send(data1)
            print ('\nConnection established!')
            print('--------------------------------------------------------\n')

        else:
            print ('Error establishing connection')

        first_msg = {"action": "hello"}
        self.sendData(pickle.dumps(first_msg))
        self.player = None
        self.players_nicks = []
        self.cli2cli_secret_src=""
        self.cli2cli_secret_dest=""
        self.cli2cli_a_src=0
        self.cli2cli_a_dst=0
        self.receiveData()
        
        # self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # self.sock.connect((host, port))
        # first_msg = {"action": "hello"}
        # self.sock.send(pickle.dumps(first_msg))
        # self.player = None
        # self.receiveData()

    def receiveData(self):
        global secret
        
        while True:
            msg = self.sock.recv(4096)
            print(msg)
            iv = 16 * b'\0'
            aes = AES.new(secret, AES.MODE_CBC, iv)
            data = aes.decrypt(msg)
            if data:
                self.handle_data(data)


    def handle_data(self, data):
        data = pickle.loads(data)
        action = data["action"]
        print("\n"+action)
        if action == "login":
            nickname = ''.join(random.choices(string.ascii_uppercase + string.digits, k=4)) #input(data["msg"])
            print("Your name is "+Colors.BBlue+nickname+Colors.Color_Off)
            msg = {"action": "req_login", "msg": nickname}
            self.player = Player(nickname,self.sock)
            self.sendData(pickle.dumps(msg))
            return
            # todo login
        elif action == "you_host":
            self.player.host=True
        elif action == "new_player":
            print(data["msg"])
            print("There are "+str(data["nplayers"])+"\\"+str(data["game_players"]))

        elif action == "waiting_for_host":
            if self.player.host:
                msg={"action":"get_nicks"}
                self.sendData(pickle.dumps(msg))
                print("Sent ", msg)
            else:
                print(data["msg"])

        elif action == "host_start_game":
            print(data["msg"])
            if not self.player.host:
                self.player.wait_value = 1
            msg = {"action": "get_deck_to_encrypt"}
            self.sendData(pickle.dumps(msg))
            print("Sent ", msg)

        elif action == "list_nicks":
            print(data["msg"])
            for i in range (len(data["msg"])):
                if data["msg"][i]!=self.player.name:
                    self.players_nicks.append(data["msg"][i])
            if self.player.host:
                input(Colors.BGreen+"PRESS ENTER TO START THE GAME"+Colors.Color_Off)                
                msg = {"action": "start_game"}
                self.sendData(pickle.dumps(msg))

        ##CIFRAGEM DO BARALHO
        elif action == "rcv_deck_to_encrypt":
            self.player.nplayers = data["nplayers"]
            self.player.npieces = data ["npieces"]
            self.player.pieces_per_player = data["pieces_per_player"]
            self.player.in_table = data["in_table"]
            self.player.deck = data["deck"]
            self.player.wait_value = 0
            print("Deck received -----")
            print(self.player.deck)
            #print("deck -> " + self.player.deck + "\n")

            #ENCRIPTAÇÃO HOST
            enc = self.player.encrypt_deck_host(self.player.deck)
            msg = {"action": "deck_encrypted", "encrypted_deck": enc}
            self.sendData(pickle.dumps(msg))

        elif action == "rcv_cipher_to_encrypt":
            print("Entra")
            print(data["cipher"])
            self.player.deck = data["cipher"]
            self.player.wait_value = 0
            # print("Deck received -----")
            # print(self.player.deck)
            # #print("deck -> " + self.player.deck + "\n")

            #ENCRIPTAÇÃO NÃO HOST
            enc = self.player.encrypt_deck_player(self.player.deck)
            print("ENC")
            print(enc)
            msg = {"action": "deck_encrypted", "encrypted_deck": enc}
            self.sendData(pickle.dumps(msg))

        elif action == "rcv_game_propreties":
            self.player.nplayers = data["nplayers"]
            self.player.npieces = data ["npieces"]
            self.player.pieces_per_player = data["pieces_per_player"]
            self.player.in_table = data["in_table"]
            self.player.deck = data["deck"]
            player_name = data["next_player"]
            if data["next_player"] == self.player.name:
                player_name = Colors.BRed + "YOU" + Colors.Color_Off
            print("deck -> " + ''.join(map(str, self.player.deck)) + "\n")
            print("hand -> " + ' '.join(map(str, self.player.hand)))
            print("in table -> " + ' '.join(map(str, data["in_table"])) + "\n")
            print("Current player ->",player_name)
            print("next Action ->", data["next_action"])

            if self.player.name == data["next_player"]:
                if data["next_action"] == "get_piece":
                    if not self.player.ready_to_play:
                        random.shuffle(self.player.deck)
                        # Mudar consoante a probabilidade de apanhar uma peça
                        prob = random.randint(1, 1)
                        if prob == 1 and len(self.player.hand) < 5:
                            print('Pick')
                            piece = self.player.deck.pop()
                            self.player.insertInHand(piece)
                            msg = {"action": "get_piece", "deck": self.player.deck}
                        elif prob == 2 and len(self.player.hand) >= 1:
                            print('Swap')
                            random.shuffle(self.player.hand)
                            piece_hand = self.player.hand.pop()
                            self.player.updatePieces(-1)
                            piece = self.player.deck.pop()
                            self.player.deck.append(piece_hand)
                            self.player.insertInHand(piece)
                            msg = {"action": "get_piece", "deck": self.player.deck}
                        else:
                            print('Pass')
                            msg = {"action": "get_piece", "deck": self.player.deck}
                        print('In hand: ' + str(len(self.player.hand)))
                        self.sendData(pickle.dumps(msg))
                if data["next_action"]=="play":
                    #input(Colors.BGreen+"Press ENter \n\n"+Colors.Color_Off)
                    msg = self.player.play()
                    self.sendData(pickle.dumps(msg))

        elif action == "end_game":
            winner = data["winner"]
            if data["winner"] == self.player.name:
                winner = Colors.BRed + "YOU" + Colors.Color_Off
            else:
                winner = Colors.BBlue + winner + Colors.Color_Off
                for l in self.player.hand:
                    self.player.score=self.player.score + int(l.values[0].value) + int(l.values[1].value)
            print(Colors.BGreen+"End GAME, THE WINNER IS: "+winner)
            msg = {"action": "game_ended", "score": self.player.score, "final_hand" : self.player.hand}
            self.sendData(pickle.dumps(msg))

        elif action == "cli2cli":
            # enviar mensagem para o manager a dizer com quem quer comunicar
            msg={"action":"start_cli2cli","source":self.player.name,"dest":self.players_nicks[random.randint(0, len(self.players_nicks)-1)]}
            self.sendData(pickle.dumps(msg))

        elif action == "wait":
            print(data["msg"])
            if self.player.wait_value == 1:
                msg = {"action": "get_deck_to_encrypt"}
                self.sendData(pickle.dumps(msg))

        elif action == "src_dh_cli2cli":
            print (data["msg"])
            # Start diffie-hellman negotiation through manager
            g = 9
            p = 1001 
            random.seed()
            self.cli2cli_a_src = random.randint(10000, 999999)
            A = (g**self.cli2cli_a_src) % p
            msg={"action" : "dst_dh_cli2cli","msg":str(A)}
            self.sendData(pickle.dumps(msg))

        elif action == "dst_dh_cli2cli":
            # calculate the public key on the destination side
            g = 9
            p = 1001 
            random.seed()
            self.cli2cli_a_dst = random.randint(10000, 999999)
            A = (g**self.cli2cli_a_dst) % p
            msg={"action" : "src_dh2_cli2cli","msg":str(A)}

            keyServer = data["msg"]
            secretDst = (int(keyServer)**self.cli2cli_a_dst) % p
            print('Shared secret: %s' % secretDst)

            # secret needs to have 16 characters
            secret=bytes (self.pad16Str(str (secretDst)),'utf-8')
            self.cli2cli_secret_dest=secret

            self.sendData(pickle.dumps(msg))

        elif action =="src_dh2_cli2cli":
            p = 1001
            keyServer = data["msg"]
            secretSource = (int(keyServer)**self.cli2cli_a_src) % p
            print('Shared secret: %s' % secretSource)

            # secret needs to have 16 characters
            secret=bytes (self.pad16Str(str (secretSource)),'utf-8')
            self.cli2cli_secret_src=secret

            msg_to_client={"msg":"What's up !!! Message from another player."}
            # encrypton with AES and the message needs to be a multiple of 16
            iv = 16 * b'\0'
            aes = AES.new(secret, AES.MODE_CBC, iv)
            encd = aes.encrypt(self.pad16Bytes(pickle.dumps(msg_to_client)))

            msg_to_manager={"action":"msg_to_dest_cli2cli","msg":encd}

            self.sendData(pickle.dumps(msg_to_manager))

        elif action == "msg_from_src_cli2cli":
            msg=data["msg"]
            iv = 16 * b'\0'
            aes = AES.new(self.cli2cli_secret_dest, AES.MODE_CBC, iv)
            data1 = aes.decrypt(msg)
            data2=pickle.loads(data1)
            print ("Message received: ",data2["msg"])

            msg={"action":"close_cli2cli"}
            self.sendData(pickle.dumps (msg))


        elif action =="disconnect":
            self.sock.close()
            print("PRESS ANY KEY TO EXIT ")
            sys.exit(0)

        elif action == "get_ready":
            msg = {"action": "send_scores"}
            self.sendData(pickle.dumps(msg))

        elif action == "rcv_game_scores":
            self.player.scores = data["scores"]
            print("My Score: "+ str(self.player.score))
            for l in self.player.scores:
                if l >= 30:
                    print('Game Over')
                    final_points = 30 - self.player.score
                    if final_points < 0:
                        final_points = 0
                    print('Final Points: ' + str(final_points))
                    msg = {"action": "game_over", "score": self.player.scores}
                    self.sendData(pickle.dumps(msg))
                if(l != self.player.score):
                    print('Others score: {}'.format(l))

            self.player.restartGame()
            # print('SIZE DO BARALHO' + str(len(self.player.deck)))
            msg = {"action": "restart_game"}
            self.sendData(pickle.dumps(msg))

        elif action == 'game_over':
            for sc in data['score']:
                print('Score: ' + str(sc))
            exit(0)



a = client('localhost', 50000)
