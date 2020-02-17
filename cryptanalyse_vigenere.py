# Sorbonne Université 3I024 2018-2019
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 2 : NOM ET NUMERO D'ETUDIANT

import sys, getopt, string, math
from frequence import hist_from_file

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Fréquence moyenne des lettres en français
# À modifier
# freq_FR = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
freq_FR = [0.09213437454330574, 0.010354490059155806, 0.030178992381545422, 0.037536932666586184, 0.17174754258773295, 0.010939058717380115, 0.0106150043524949, 0.010717939268399616, 0.07507259453174145, 0.0038327371156619923, 6.989407870073262e-05, 0.06136827190067416, 0.026498751437594118, 0.07030835996721332, 0.04914062053233872, 0.023697905083841123, 0.010160057440224678, 0.06609311162084369, 0.07816826681746844, 0.0737433362349966, 0.06356167517044624, 0.016450524523290613, 1.1437212878301701e-05, 0.004071647784675406, 0.0023001505899695645, 0.0012263233808401269]

def calculate_freq_FR():
    # this is what I used to calculate freq_FR from germinal file
    freq_FR = []
    freqs = hist_from_file("germinal.txt")
    keys = sorted(freqs)

    for key in keys:
        freq_FR.append(freqs[key])

# Chiffrement César
def chiffre_cesar(txt, key):
    """
        @params: txt is a string (all upper_cases)
                 key is an int

        return : encrypted txt
    """

    assert(isinstance(key, int) and key >= 0)
    encrypted = ""
    length = len(txt)
    txt = txt.upper()

    for i in range(length):
        encrypted += alphabet[(alphabet.index(txt[i]) + key) % 26]

    return encrypted

# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
        @params: txt is a string (all upper_cases)
                 key is an int

        return : plain txt
    """

    assert(isinstance(key, int) and key >= 0)
    
    plain = ""
    length = len(txt)
    txt = txt.upper()

    for i in range(length):
        plain += alphabet[(alphabet.index(txt[i]) - key) % 26]

    return plain

# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
        @params: txt -> string 
                 key -> list of ints
    """
    
    # assert that the key argument is a list of ints
    assert(isinstance(key, list) and len(key) > 0)
    for i in range(len(key)):
        assert(isinstance(key[i], int) and key[i] >= 0)

    # transform the text to uppercases just to be sure ( assuming it's only alphabetical )
    txt = txt.upper()
    txt_length = len(txt)

    crypted = ""
    len_keys = len(key)

    for i in range(txt_length):
        crypted += chiffre_cesar(txt[i], key[i % len_keys]) # each char is encrypted with cesar cipher

    return crypted

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
        @params: txt -> string 
                 key -> list of ints
    """
    
    # assert that the key argument is a list of ints
    assert(isinstance(key, list) and len(key) > 0)
    for i in range(len(key)):
        assert(isinstance(key[i], int) and key[i] >= 0)

    # transform the text to uppercases just to be sure ( assuming it's only alphabetical )
    txt = txt.upper()
    txt_length = len(txt)

    plain = ""
    len_keys = len(key)

    for i in range(txt_length):
        plain += dechiffre_cesar(txt[i], key[i % len_keys]) # each char is decrypted with cesar cipher

    return plain

# Analyse de fréquences
def freq(txt):
    """
        @params: txt -> a string
        return the frequency of each letter of the alphabet
    """
    txt = txt.upper()
    hist = []

    for char in alphabet:
        hist.append(txt.count(char))

    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
        @params: txt -> a string
        return the index of the most frequent char in txt
    """

    txt = txt.upper() # transform txt to uppercase in order for this to work

    # for max, key is the value of count, then I need to take the corresponding character by taking the index 0 of the tuple (char, count(char)) -> pass it to index method to get its index
    return alphabet.index( max( [(char, txt.count(char)) for char in alphabet] , key = lambda x : x[1])[0] )

# indice de coïncidence
def indice_coincidence(hist):
    """
        @params: hist -> list of frequencies of some text
        return "indice de coincidence"
    """
    s = 0.0
    
    msg_len = sum([x for x in hist if x > 0])

    for i in range(len(alphabet)):
        s += ( hist[i] * (hist[i] - 1) )

    s /= (msg_len * (msg_len - 1))
    return s

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
        on suppose que la clef cherchée est au plus de longueur 20.  On découpe le texte en colonnes (max col width = 20)

        @params: cipher -> a encrypted txt (string)

        returns the length of the key
    """
    LEN_LIMIT = 20
    cipher_len = len(cipher)

    strings = []

    if indice_coincidence(freq(cipher)) > 0.06: # length(key) = 1
        return 1

    for i in range(2, LEN_LIMIT+1): # length(key) = i
        for k in range(i):
            j = k
            s = ""

            while j < cipher_len:
                s += cipher[j]
                j += i

            strings.append(s)

        avg_index = sum([indice_coincidence(freq(x)) for x in strings]) / len(strings)

        if avg_index > 0.06:
            return i

        strings = []

    return 0
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
        cut the cipher into multiple strings within key_length columns.
        calculate the shift size of each column between E (the most freq char in french) and most_freq_char in that column
        return the list of decalage
    """
    decalages=[0]*key_length
    columns = []
    cipher_len = len(cipher)
    e_ord = ord('E')

    for k in range(key_length):
        j = k
        s = ""

        while j < cipher_len:
            s += cipher[j]
            j += key_length

        columns.append(s)

        # most_freq_char = sorted([(char, s.count(char)) for char in set(s)], key = lambda x : x[1])[-1][0] # [-1] to get most freq tuple (char, count(char)) -> [0] to get the actual char
        # weird bug if I used the previous line -> maybe sorted function doesn't perform a stable sort

        most_freq_char = alphabet[lettre_freq_max(s)]
        decalages[k] = (ord(most_freq_char) - e_ord) % 26

    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    Documentation à écrire
    """
    guessed_key_length = longueur_clef(cipher)
    decalages = clef_par_decalages(cipher, guessed_key_length)
    columns = []
    cipher_len = len(cipher)

    for k in range(guessed_key_length):
        j = k
        s = ""

        while j < cipher_len:
            s += cipher[j]
            j += guessed_key_length

        columns.append(s)

    plain_text = ""

    # assumption -> all the cols have the same length

    for i in range(len(columns[0])): 
        for j in range(guessed_key_length):
            try:
                plain_text += alphabet[ (alphabet.index(columns[j][i]) - decalages[j]) % 26]
            except IndexError:
                """first_col = columns[0]

                for i in range(1, len(columns)):
                    if len(columns[0]) == len(columns[i]):
                        columns[0] = columns[i]
                    else:
                        print("yikes")
                        print(columns[0])
                        print(columns[i])
                        break"""
                pass


    return plain_text


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    Documentation à écrire
    """
    decalages=[0]*key_length
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################


### fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    Documentation à écrire
    """
    return 0.0

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    Documentation à écrire
    """
    key=[0]*key_length
    score = 0.0
    return (score, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    Documentation à écrire
    """
    return "TODO"


################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
    main(sys.argv[1:])

