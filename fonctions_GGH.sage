from itertools import product
print("Fichier chargé")
"""
Génère une matrice unimodulaire aléatoire.

Paramètres :
- n (int) : Taille de la matrice carrée (n x n).
- nbc (int) : Nombre de matrices unimodulaires multipliées entre elles (valeur suggérée : 2n).

Retour :
- Matrix : Une matrice unimodulaire de dimensions n x n (déterminant égal à ±1).
"""
def generate_unimodular_matrix(n, nbc = 1):
    Ures = matrix.identity(n)
    dist = GeneralDiscreteDistribution([1/7, 5/7, 1/7])
    
    for i in range(nbc):
        U = matrix.identity(n)
        ind = randint(0,n-1)
        
        if randint(0,1): # Modifie une ligne ou une colonne avec 50% de chances
            U[ind] = [dist.get_random_element() - 1 for _ in range(n)]
            U[ind, ind] = 1
        else:
            for i in range(n):
                U[i, ind] = dist.get_random_element() - 1
            U[ind, ind] = 1
        Ures *= U
    return Ures



"""
Génère une clé publique et une clé privée pour un chiffrement basé sur des matrices.

Paramètres :
- n (int) : Taille des matrices carrées (n x n).
- l (int) : Amplitude des coefficients dans la matrice privée (valeur par défaut : 4).
- debug (bool) : Si True, affiche les matrices générées pour le débogage.
- nbc (int) : Nombre de matrices unimodulaires multipliées entre elles.

Retour :
- Bpriv (Matrix) : Matrice privée.
- Bpub (Matrix) : Matrice publique.
- U (Matrix) : Matrice unimodulaire utilisée pour transformer Bpriv en Bpub.
"""
def KeyGen(n, l = 4, debug = False, nbc = 1):
    k = round(sqrt(n)) * 4
    IDk = k * matrix.identity(n)
    Bpriv = IDk + MatrixSpace(ZZ, n,n).random_element(x = -l, y = l + 1 , distribution = 'uniform')
    while Bpriv.det() == 0:
        Bpriv = IDk + MatrixSpace(ZZ, n,n).random_element(x = -l, y = l + 1 , distribution = 'uniform')
    Bpriv = Bpriv.LLL()
        
    U = generate_unimodular_matrix(n, nbc=nbc)
        
    Bpub = U * Bpriv
    
    if(debug):
        print("Matrice B (clé privée) :")
        print(Bpriv)
        print("\nMatrice U (unimodulaire) :")
        print(U)
        print("\nMatrice B' (clé publique) :")
        print(Bpub)

    return Bpriv, Bpub, U



"""
Chiffre un message à l'aide de la clé publique.

Paramètres :
- Bpub (Matrix) : Clé publique utilisée pour le chiffrement.
- m (vector) : Message à chiffrer, sous la forme d'un vecteur.
- breakPoint (int) : Nombre maximal d'itérations pour ajuster l'erreur (valeur par défaut : 128).

Retour :
- c (vector) : Message chiffré
"""
def Cipher(Bpub, m, breakPoint = 128):
    n = Bpub.nrows()
    r = round(min([Bpub.column(i).norm(2) for i in range(n)]) / 6)
    err = vector(ZZ, [randint(-1, 1) for _ in range(n)])
    boucle = 0
    while err.norm(2) >= r:
        boucle += 1
        err = vector(ZZ, [randint(-1, 1) for _ in range(n)])
        if(boucle > breakPoint):
            err = vector(ZZ, [randint(0,1) if(i < r) else 0 for i in range(n)])
            break
    return m*Bpub + err

"""
Déchiffre un message à l'aide de la clé privée.

Paramètres :
- Bpriv (Matrix) : Matrice privée pour le déchiffrement.
- U (Matrix) : Matrice unimodulaire utilisée dans la génération des clés.
- c (vector) : Message chiffré.

Retour :
- m (vector) : Message clair, sous la forme d'un vecteur.
"""
def Decipher(Bpriv, U, c):
    m_prim = c * Bpriv.inverse()
    m_sec = m_prim.apply_map(lambda x: round(x))
    
    # Autre version qui peut être préférable sur la version consôle de sage
    # m_sec = m_prim.apply_map(lambda x: math.ceil(x) if abs(x % 1) == 0.5 else round(x))
    
    m = m_sec * U.inverse()

    return m



"""
Teste les fonctions de génération de clé, de chiffrement et de déchiffrement.

Paramètres :
- n (int) : Taille des matrices carrées utilisées pour le chiffrement.
- nb (int) : Nombre de tests à effectuer.
"""
def test_encryption_system(n, nb):
    good = 0
    ERR = []
    nberr = 0

    for i in range(nb):
        Bpriv, Bpub, U = KeyGen(n, nbc = 2 * n)

        m = vector(ZZ, [randint(0, 1) for _ in range(n)])

        c = Cipher(Bpub, m)

        m2 = Decipher(Bpriv, U, c)

        if m == m2:
            good += 1
        else:
            nberr += 1
            e = m - m2
            print(f"Erreur détectée : {e}")
            ERR.append(sum(1 for j in e if j != 0))

    taux_reussite = (good / nb) * 100
    taux_erreur_bits = (sum(ERR) / (nberr * n)) * 100 if nberr > 0 else 0

    print(f"Le taux de réussite dans le déchiffrement pour des matrices de taille {n} est de {round(taux_reussite)}%")
    if nberr > 0:
        print(f"Le taux de bits incorrectement déchiffrés en cas d'erreur est de {round(taux_erreur_bits)}%")



"""
Chiffre une chaîne de caractères en utilisant une clé publique.

Paramètres :
- message (str) : Chaîne à chiffrer.
- Bpub (Matrix) : Matrice publique générée.
- size (int) : Taille des blocs pour le chiffrement (par défaut : 112).

Retour :
- list : Liste des vecteurs chiffrés.
"""
def encrypt_string(message, Bpub, size=112):
    # Convertion de chaque caractère en 8 bits
    m_bin = ''.join([bin(ord(char))[2:].zfill(8) for char in message])

    # Ajouter du padding
    n_max = len(m_bin)
    r = n_max % size
    m_bin += "0" * (size - r) if r != 0 else ""

    # Découpe en vecteurs de taille fixe
    list_vec = [vector([int(bit) for bit in m_bin[i * size:(i + 1) * size]]) 
                for i in range(len(m_bin) // size)]

    C = [Cipher(Bpub, m) for m in list_vec]
    return C



"""
Déchiffre une liste de vecteurs chiffrés.

Paramètres :
- C (list) : Liste des vecteurs chiffrés.
- Bpriv (Matrix) : Matrice privée générée.
- U (Matrix) : Matrice unimodulaire utilisée pour la clé publique.
- size (int) : Taille des blocs pour le chiffrement (par défaut : 112).

Retour :
- str : Chaîne déchiffrée.
"""
def decrypt_string(C, Bpriv, U, size=112):
    M2 = [Decipher(Bpriv, U, c).list() for c in C]

    # Retrait du padding
    while M2[-1][-8:] == [0] * 8:
        M2[-1] = M2[-1][:-8]

    # Reconstitution de la chaîne binaire
    M2 = ''.join([''.join(map(str, block)) for block in M2])
    message = ''.join([chr(int(M2[i:i+8], 2)) for i in range(0, len(M2), 8)])
    return message




"""
Teste le chiffrement et le déchiffrement d'une chaîne de caractères.

Paramètres :
- message (str) : Chaîne à chiffrer et déchiffrer.
- size (int) : Taille des blocs pour le chiffrement (par défaut : 112).
- debug (bool) : Si True, affiche les matrices générées pour le débogage.
"""
def test_global_system(message, size = 8 * 14, debug = False, Bpriv= None, Bpub = None, U = None):
    print("Message d'origine :", message)
    
    if (Bpriv == None or Bpub == None or U == None) or (Bpriv.ncols() % 8 != 0):
        if(size % 8 != 0):
            size = 8 * 14
        Bpriv, Bpub, U = KeyGen(size, debug=debug)

    encrypted_message = encrypt_string(message, Bpub, size)
    print("\nMessage chiffré :", encrypted_message)

    decrypted_message = decrypt_string(encrypted_message, Bpriv, U, size)
    print("\nMessage déchiffré :", decrypted_message)

    if message == decrypted_message:
        print("\nLe message a été correctement déchiffré.")
    else:
        print("\nErreur dans le déchiffrement.")



"""
Génère tous les vecteurs possibles de dimension donnée avec des coefficients
dans {0, -1, 1} et une norme inférieure à une borne.

Paramètres :
- n (int) : Taille des vecteurs à générer.
- r (int) : Borne supérieure pour la norme Euclidienne.

Retour :
- (iterator) : Itérateur sur les vecteurs respectant les contraintes.
"""
def generate_vectors_iterative(n, r):
    for v in product([0, -1, 1], repeat=n):
        v = vector(v)
        if v.norm(2) < r:
            yield v

"""
Effectue une attaque par force brute pour déchiffrer un message.

Paramètres :
- Bpub (Matrix) : Matrice publique utilisée pour le chiffrement.
- c (vector) : Message chiffré.
- borneInf (int) : Borne inférieure des coefficients des vecteurs candidats (par défaut : 0).
- borneSup (int) : Borne supérieure exclusive des coefficients des vecteurs candidats (par défaut : 2).
  C'est-à-dire que l'on définit l'espace des coefficients du vecteur m comme [borneInf, borneSup[

Retour :
- candidates (list) : Liste des messages candidats sous forme de vecteurs.

Note : Les bornes définissent l'espace de recherche des messages candidats. Avec les valeurs 
par défaut, la fonction cherche un message binaire.
"""

def brute_force_attack(Bpub, c, m, borneInf=0, borneSup=2):
    n = Bpub.ncols()
    r = round(min([Bpub.column(i).norm(2) for i in range(n)]) / 6)
    Bpub_inv = Bpub.inverse()
    candidates = []
    
    c_prim = c * Bpub_inv
    for e in generate_vectors_iterative(n, r):
        possible_m = c_prim - Bpub_inv * e
        possible_m = possible_m.apply_map(lambda x: round(x))

        if all(x in range(borneInf,borneSup) for x in possible_m):
            candidates.append(possible_m)

            if possible_m == m:
                print("Message récupéré :", possible_m)
                return candidates

    print("Message non trouvé, augmentation de la norme maximale nécessaire.")
    return candidates



"""
Effectue une attaque par l'algorithme Nearest-Plane sur un message chiffré.

Paramètres :
- c (vector) : Le message chiffré.
- Bpub (Matrix) : La matrice publique utilisée pour le chiffrement.

Retour :
- e_new (vector) : Une approximation de l'erreur.
"""
def nearest_plane_error(c, Bpub):
    n = Bpub.nrows()
    Bpub_lll = Bpub.LLL()
    
    Bpub_inv = Bpub_lll.inverse()

    c_prim = c * Bpub_inv
    
    coefs = [round(i) for i in c_prim.list()]

    Bnew = Bpub_lll
    e_new = c

    for i in range(n-1, -1, -1):
        e_new = e_new - coefs[i] * Bnew[i]
        Bnew = matrix(list(Bnew)[:i])
        
    return e_new



"""
Effectue une attaque complète pour déchiffrer un message à l'aide de l'algorithme Nearest-Plane.

Paramètres :
- c (vector) : Message chiffré.
- Bpub (Matrix) : Matrice publique utilisée pour le chiffrement.

Retour :
- m (vector) : Message clair approximé.
"""
def nearest_plane_attack(Bpub, c):
    error = nearest_plane_error(c, Bpub)
    
    Bpub_inv = Bpub.inverse()
    
    m_prim = c * Bpub_inv - Bpub_inv * error
    m = m_prim.apply_map(lambda x: round(x))
    
    return m



""" 
Effectue une attaque d'embedding pour déchiffrer un message à l'aide de la réduction LLL.

Paramètres :
- c (vector) : Message chiffré.
- Bpub (Matrix) : Matrice publique utilisée pour le chiffrement.

Retour :
-m (vector) : Message clair approximé.
"""
def embedding_attack(Bpub, c):
    n = Bpub.nrows()
    
    B = matrix(Bpub.rows() + [c]).transpose()
    B = matrix(B.rows() + [[ i == n for i in range(n+1)]]).transpose().LLL()
    
    e = vector(B[0][:n])
    
    m = (c - e) * Bpub.inverse()
    
    
    return m.apply_map(round)
