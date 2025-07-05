# 🚨 Educational Project Notice 🚨

**This project is for educational purposes only. It is not intended for use in real-world cryptographic applications. Do not use this implementation for securing sensitive data.**

---

An academic implementation of the GGH (Goldreich-Goldwasser-Halevi) lattice-based cryptosystem with cryptanalysis attacks. This project explores post-quantum cryptography concepts and demonstrates both the encryption system and its known vulnerabilities.

## 📖 About

The GGH cryptosystem is a lattice-based public-key cryptosystem that was proposed in 1997. While it has been cryptanalyzed and is not secure for practical use, it serves as an excellent educational tool for understanding:

- Lattice-based cryptography fundamentals
- Post-quantum cryptographic concepts
- Common cryptanalysis techniques
- The importance of proper parameter selection in cryptographic systems

## 🏗️ Project Structure

### Core Implementation Files

- **[`fonctions_GGH.sage`](fonctions_GGH.sage)** - Main cryptosystem implementation containing:
  - Key generation (`KeyGen`)
  - Encryption (`Cipher`) and decryption (`Decipher`) functions
  - String encryption/decryption with binary encoding
  - System validation functions

- **[`Projet_GGH.ipynb`](Projet_GGH.ipynb)** - Complete Jupyter notebook with:
  - Full implementation and documentation
  - Interactive examples and visualizations
  - Performance analysis
  - Pre-executed results for immediate viewing

### Test Files

- **[`test_cryptosysteme.sage`](test_cryptosysteme.sage)** - Unit tests for the cryptosystem functions
- **[`test_attaques.sage`](test_attaques.sage)** - Implementation and evaluation of cryptanalysis attacks
- **[`test.sage`](test.sage)** - Comprehensive test suite combining both cryptosystem and attack tests

### Documentation

- **[`main.tex`]([Réseau Euclidien][Compte-Rendu]/main.tex)** - Complete technical report in French
- **[`Réseau_Euclidien_Compte_Rendu.pdf`](Réseau_Euclidien_Compte_Rendu.pdf)** - Compiled PDF report

## 🛠️ Features

### Cryptosystem Implementation
- **Key Generation**: Creates private/public key pairs using lattice reduction
- **Encryption**: Adds controlled error vectors to plaintext
- **Decryption**: Recovers plaintext using private key and rounding
- **Message Handling**: Binary encoding with padding for arbitrary text

### Cryptanalysis Attacks
1. **Brute Force Attack**: Exhaustive search on error vectors
2. **Nearest Plane Attack**: Uses LLL lattice reduction
3. **Embedding Attack**: Constructs augmented matrices for error recovery

### Performance Testing
- Matrix generation optimization analysis
- Memory usage optimization with generator functions
- Performance comparison of different implementation approaches

## 🚀 Usage

### Prerequisites
- SageMath (version 9.5 or higher)
- Jupyter Notebook (for interactive version)

### Console Version

1. Load the main functions:
```bash
sage: load("fonctions_GGH.sage")
```

2. Run specific tests:
```bash
# Test cryptosystem only
sage: load("test_cryptosysteme.sage")

# Test attacks only  
sage: load("test_attaques.sage")

# Full test suite
sage: load("test.sage")
```

## 📊 Example Usage

```python
# Generate keys
Bpriv, Bpub, U = KeyGen(n=16, debug=True)

# Encrypt a message
message = "Hello, cryptography!"
encrypted = encrypt_string(message, Bpub, size=16)

# Decrypt the message
decrypted = decrypt_string(encrypted, Bpriv, U, size=16)

# Demonstrate attacks
m = vector(ZZ, [randint(-5, 5) for _ in range(16)])
c = Cipher(Bpub, m)

# Brute force attack
recovered_bf = brute_force_attack(Bpub, c, m)

# Nearest plane attack
recovered_np = nearest_plane_attack(Bpub, c)

# Embedding attack
recovered_emb = embedding_attack(Bpub, c)
```

## 📈 Performance Notes

- Optimized for matrices up to size 200×200
- Memory-efficient implementation using generators
- Execution time ~2.5 minutes for full test suite on size 200 matrices
- Debug mode should be disabled for large matrix sizes

## 🔬 Technical Details

### Key Parameters
- **Matrix size**: n×n (typically 16-200)
- **Coefficient range**: [-4, 4] for private key generation
- **Error range**: {-1, 0, 1} for encryption errors
- **Unimodular matrices**: Generated using elementary operations

### Security Notes
This implementation uses simplified parameters that make cryptanalysis feasible for educational purposes. The attacks succeed with high probability due to:
- Small error vectors
- Reduced lattice dimensions
- Optimized attack parameters

## 📚 References

- Goldreich, O., Goldwasser, S., & Halevi, S. (1997). *Public-key cryptosystems from lattice reduction problems*
- Galbraith, S. D. *Mathematics of public key cryptography*, Part IV Lattices

## ⚠️ Limitations

- **Not cryptographically secure**: Vulnerable to multiple attack vectors
- **Educational parameters**: Simplified for learning purposes
- **Performance bounds**: Optimized for matrices up to 200×200
- **Memory requirements**: ~2GB RAM for largest test cases

---

*Developed as part of Master's coursework in Information Mathematics and Cryptography at University of Rennes*
