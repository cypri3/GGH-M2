def test(n = 16):
    Bpriv, Bpub, U = KeyGen(n, debug = True, nbc=2*n)
    message = "Ceci est un test de chiffrement et déchiffrement"
    print("\nVérification du système de chiffrement :\n")
    test_global_system(message, size = n, debug = False, Bpriv = Bpriv, Bpub = Bpub, U = U)

    print("\nRéalisation des attaques :\n")
    Bpriv, Bpub, U = KeyGen(n, nbc=4) # nbc faible pour des raisons de performances
    
    print("1. Attaque par force brute")
    
    m = vector(ZZ, [randint(-5, 5) for _ in range(n)])
    print("Message recherché :",m)
    c = Cipher(Bpub, m)
    candidats = brute_force_attack(Bpub, c, m, borneInf = -5, borneSup = 6)
    if len(candidats) > 1:
        print("Liste des premiers candidats :", candidats)
        
    print("\n2. Attaque nearest plane :\n")
    
    m_recovered = nearest_plane_attack(Bpub, c)
    print("Message recherché :", m)
    print("Message récupéré :", m_recovered)
    if m == m_recovered:
        print("Le message à été correctement retrouvé.")
    else:
        print("Le message retrouvé ne correspond pas au message original.")
        
    print("\n3. Attaque embedding :\n")
    
    m_recovered = embedding_attack(Bpub, c)
    print("Message recherché :", m)
    print("Message récupéré :", m_recovered)
    if m == m_recovered:
        print("Le message à été correctement retrouvé.")
    else:
        print("Le message retrouvé ne correspond pas au message original.")
test()