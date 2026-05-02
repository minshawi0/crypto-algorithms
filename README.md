# Cryptography Algorithms

A collection of classical cryptography algorithms implemented in pure Java for educational purposes.
Built by [@minshawi0](https://github.com/minshawi0) and [@omarrashraff](https://github.com/omarrashraff)

---

## Algorithms

### AES-128 (Advanced Encryption Standard)
A pure Java implementation of AES-128 with full 10-round encryption and decryption.
Built without any external libraries to demonstrate the core AES operations including
SubBytes, ShiftRows, MixColumns, and AddRoundKey.

### DES (Data Encryption Standard)
A complete implementation of the classic 64-bit DES algorithm with 56-bit keys.
Covers both encryption and decryption using the full Feistel structure including
initial permutation, key scheduling, and 16 rounds of substitution and permutation.

### LFSR (Linear Feedback Shift Register)
A Java implementation of LFSR, a core component in stream ciphers, pseudo-random
number generation, and CRC error detection. Demonstrates how shift register feedback
produces cryptographically useful bit sequences.

---

## Structure

```
crypto-algorithms/
├── AES-Algorithm/
├── DES-Algorithm/
└── LFSR-Algorithm/
```

---

## Purpose

These implementations are built for learning and understanding the mathematical
foundations behind symmetric and stream cipher cryptography. No external cryptographic
libraries are used — everything is implemented from scratch.

---

## Authors

- [@minshawi0](https://github.com/minshawi0)
- [@omarrashraff](https://github.com/omarrashraff)
