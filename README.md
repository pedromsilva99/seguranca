# seguranca

Projeto da unidade curricular Segurança

Jogo seguro de dominó com vários clientes

Avaliação final 15

Problemas:

Diffie Hellman com números primos demasiado pequenos, levando a que os segredos partilhados possam ser descobertos a partir de "brute force"


Não fazemos o Bit Commitment, o que leva a que o jogador não possa confirmar que escolheu realmente aquelas peças. O que não compromete a segurança, pois o último jogador a decifrar e a obter os 15 pseudónimos desconhece as peças e não tirará vantagem nenhuma em alterar os pseudónimos.

Servidor guarda os pontos num ficheiro, mas isso é "impossível" dado que o servidor não terá acesso ao cartão. No entanto, se for o jogador a alterar o ficgeiro pode preencher esse ficheiro da maneira que pretender, o que causa inconsistências, mas o professor disse que não nos devíamos focar nesse aspeto.

Participantes:

Pedro Silva

Pedro Gonçalves

André Almeida

Rita Amante

Professor: André Zúquete
