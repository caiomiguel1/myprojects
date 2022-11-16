"""
POR: CAIO MIGUEL GONGORA DARZI
RGA: 2019.1905.002-7
TÍTULO: CIGRAGEM E DECIFRAGEM UTILIZANDO REDES DE FEISTEL E SUBSTITUIÇÕES MONOALFABÉTICAS
"""

#Importa a função exit da biblioteca Sys para encerrar o programa quando houver algum erro de entrada
from sys import exit


#Esse método é responsável por rotacionar a chave inicial Ki à direita quando necessário
def shifter(key):
    new_key = [0]
    for i in range(len(key) - 1):
        new_key.append(key[i])

    new_key[0] = key[len(key) - 1]
    return new_key


#Essa á a função F da rede Feistel, que cifra cada ‘byte’ individualmente por uma substituição monoalfabética
def mono_alphabetic(key, text):
    encrypted = []
    for character in text:
        encrypted.append(key[character])

    return encrypted


#Essa função é responsável por informar as informações de uso do código para o usuário
def informations():
    print('Por favor, envie cada comando e seus valores em uma única linha (Ex.: I 2 8 1 2 3 4 5 6 7 8), e, no final, '
          'uma linha vazia para iniciar o processo')


#Esse método é responsável por estruturar cada rodada da rede de Feistel'
def feistel(left, right, key):

    XOR = [left[i] ^ (mono_alphabetic(key, right)[i]) for i in range(len(left))]
    left, right = right, XOR

    return left, right


#Essa é a classe Principal do programa, que realiza, de fato, as operações de crifa e decriframento.
class Crypt:
    def __init__(self):
        self.initialize_command, self.crypt_command, self.decrypt_command = [], [], []
        self.n_of_rounds = 0
        self.size_of_k = 0
        self.initial_keys = []
        self.keys = []
        self.PA, self.PB = [], []
        self.left_c, self.right_c, self.left_d, self.right_d = [], [], [], []
        self.result = []

    # Esse método é reponsável por ler as informações utilizadas a partir da linha de comando e, se necessário,
    # apontar Erro(E).
    def __read(self):
        lines = []
        while True:
            user_input = input()
            if user_input == '':
                break
            else:
                lines.append(user_input)
        for item in lines:
            if item[0] == 'I':
                self.initialize_command = []
                self.initialize_command.append(item.split()[1:])
                if int(self.initialize_command[0][0]) < 2 or int(self.initialize_command[0][0]) > 32:
                    print('E')
                    exit()
                if int(self.initialize_command[0][1]) < 8 or int(self.initialize_command[0][1]) > 32:
                    print('E')
                    exit()
                for byte in self.initialize_command[0][2:]:
                    if int(byte) > 255 or int(byte) < 0:
                        print('E')
                        exit()
            elif item[0] == 'C':
                c = item.split()[1:]
                self.crypt_command.append(c)
                for byte in c:
                    if int(byte) > 255 or int(byte) < 0:
                        print('E')
                        exit()
            elif item[0] == 'D':
                d = item.split()[1:]
                self.decrypt_command.append(d)
                for byte in d:
                    if int(byte) > 255 or int(byte) < 0:
                        print('E')
                        exit()
            else:
                print('E')

    #Esse método é responsável por informar à classe as informações passadas na linha de comando
    def __initialize(self):
        self.n_of_rounds = int(self.initialize_command[0][0])
        self.size_of_k = int(self.initialize_command[0][1])
        initial_key = [int(self.initialize_command[0][i]) for i in range(2, self.size_of_k + 2)]
        self.initial_keys.append(initial_key)

    #Esse método é responsável por gerar PA e PB
    def __get_pa_and_pb(self):
        for k in range(2):
            for i in range(256):
                if i % 2 == 0:
                    self.PA.append(i)
                else:
                    self.PB.append(i)
        self.PA = tuple(self.PA)
        self.PB = tuple(self.PB)

    #Esse método é responsável por gerar as chaves iniciais Ki que serão repassadas para a função análoga a RC4
    def __generate_initial_keys(self):
        for i in range(1, self.n_of_rounds):
            if i % 2 == 0:
                key = shifter(self.initial_keys[i - 1])
                self.initial_keys.append(key)
            else:
                self.initial_keys.append(self.initial_keys[i - 1])

    # Esse método é responsável por gerar as chaves por uma técnica parecida com a RC4, que serão utilizadas na
    # rede de Feistel
    def __generate_keys(self):
        for n in range(self.n_of_rounds):
            T = [0] * 256
            if n % 2 == 0:
                S = list(self.PA)
            else:
                S = list(self.PB)

            for i in range(256):
                T[i] = self.initial_keys[n][i % self.size_of_k]
            j = 0
            for i in range(256):
                j = (j + S[i] + T[i]) % 256
                S[i], S[j] = S[j], S[i]

            self.keys.append(S)

    # Esse método é responsável por conectar todas as rodadas da rede de Feistel e gerar o último par esquerda,
    # direita dos textos cifrados ou decifrados
    def __run(self, n, reverse=False):
        if not reverse:
            self.left_c = [int(self.crypt_command[n][i]) for i in range(0, int((len(self.crypt_command[n]) / 2)))]
            self.right_c = [int(self.crypt_command[n][i]) for i in
                            range(int((len(self.crypt_command[n]) / 2)), (len(self.crypt_command[n])))]
            for i in range(self.n_of_rounds):
                self.left_c, self.right_c = feistel(self.left_c, self.right_c, self.keys[i])
            self.left_c, self.right_c = self.right_c, self.left_c
        else:
            self.left_d = [int(self.decrypt_command[n][i]) for i in range(0, int(len(self.decrypt_command[n]) / 2))]
            self.right_d = [int(self.decrypt_command[n][i]) for i in
                            range(int(len(self.decrypt_command[n]) / 2), (len(self.decrypt_command[n])))]
            for i in range(self.n_of_rounds - 1, -1, -1):
                self.left_d, self.right_d = feistel(self.left_d, self.right_d, self.keys[i])
            self.left_d, self.right_d = self.right_d, self.left_d

    #Esse método é responsável por cifrar os textos claros
    def __encrypt(self):
        for i in range(len(self.crypt_command)):
            self.__run(i)
            result = 'C ' + ' '.join(map(str, self.left_c + self.right_c))
            self.result.append(result)

    #Esse método é responsável por decifrar os textos cifrados
    def __decrypt(self):
        for i in range(len(self.decrypt_command)):
            self.__run(i, reverse=True)
            result = 'C ' + ' '.join(map(str, self.left_d + self.right_d))
            self.result.append(result)

    #Esse método é responsável por escrever na tela os resultados
    def __write_answer(self):
        for item in self.result:
            print(item)

    #Esse método é responsável por chamar todos os métodos da classe
    def main(self):
        informations()
        self.__read()
        self.__initialize()
        self.__get_pa_and_pb()
        self.__generate_initial_keys()
        self.__generate_keys()
        self.__encrypt()
        self.__decrypt()
        self.__write_answer()


#Essa estrutura é responsável por construir a classe e chamar o método main() dela
if __name__ == '__main__':
    test = Crypt()
    test.main()
