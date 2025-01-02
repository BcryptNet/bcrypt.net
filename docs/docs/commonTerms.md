---
uid: commonTerms
---

# Concepts & Common Terms

## Hashing

Hashing is the process of taking an input (or 'message') and returning a fixed-size string of bytes. The output is typically a 'digest' that is unique to the input. Hashing is a one-way function, meaning that the original input cannot be derived from the output. Hashing is used in many applications, including password storage, digital signatures, and data integrity verification.

## Entropy

Entropy is a measure of the randomness or unpredictability of data. In the context of password hashing, entropy is a measure of the strength of a password. A password with high entropy is more secure than a password with low entropy. Entropy is typically measured in bits, with higher values indicating stronger passwords.

## Work Factor

The work factor is a parameter used in password hashing algorithms to control the computational cost of generating a hash. A higher work factor increases the time and resources required to hash a password, making it more difficult for attackers to crack the hash. The work factor is often expressed as a number of rounds or iterations, with higher values indicating stronger hashes.

## Salt

A salt is a random value that is added to a password before hashing to prevent common attacks like rainbow tables and precomputed hash attacks. Salting ensures that each password hash is unique, even if two users have the same password. Salts are typically stored alongside the password hash in a secure database.

## Hash Collision

A hash collision occurs when two different inputs produce the same hash output. Hash functions are designed to minimize the likelihood of collisions, but they are still possible due to the finite size of the output space. Collisions can be exploited by attackers to bypass security measures or forge digital signatures.

## Rainbow Table

A rainbow table is a precomputed table of password hashes and their corresponding plaintext passwords. Rainbow tables are used in password cracking attacks to quickly look up the plaintext password for a given hash. Salting and strong hashing algorithms like bcrypt are used to protect against rainbow table attacks.

## Key Derivation Function (KDF)

A key derivation function is a cryptographic algorithm used to derive one or more secret keys from a master key or password. KDFs are commonly used in password hashing to generate secure cryptographic keys from user passwords. KDFs like bcrypt are designed to be slow and computationally intensive to resist brute force attacks.

