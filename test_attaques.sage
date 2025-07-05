print("1. Attaque par force brute")
n = 5
Bpriv, Bpub, U = KeyGen(n, nbc=1)

m = vector(ZZ, [randint(0, 1) for _ in range(n)])
print("Message recherché :",m)
c = Cipher(Bpub, m)
candidats = brute_force_attack(Bpub, c, m)
if len(candidats) > 1:
    print("Liste des premiers candidats :", candidats)


print("\n2. Attaque nearest plane :\n")
n = 200
Bpriv, Bpub, U = KeyGen(n)
m = vector([randint(-n^2,n^2) for i in range(n)])

c = Cipher(Bpub, m)

m_recovered = nearest_plane_attack(Bpub, c)

print("Message recherché :", m)
print()
print("Message récupéré :", m_recovered)
print()
if m == m_recovered:
    print("Le message à été correctement retrouvé.")
else:
    print("Le message retrouvé ne correspond pas au message original.")


print("\n3. Attaque embedding :\n")
n = 200
Bpriv, Bpub, U = KeyGen(n)
m = vector([randint(-n^2,n^2) for i in range(n)])

c = Cipher(Bpub, m)

m_recovered = embedding_attack(Bpub, c)

print("Message recherché :", m)
print()
print("Message récupéré :", m_recovered)
print()
if m == m_recovered:
    print("Le message à été correctement retrouvé.")
else:
    print("Le message retrouvé ne correspond pas au message original.")