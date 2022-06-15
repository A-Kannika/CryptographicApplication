## CryptographicApplication

# Introduction:
The Cryptographic Library & App is a project of TCSS 487 Cryptography course, in Spring 2022, 
at the University of Washington Tacoma. This project aims to implement (in Java) a library and an app 
for asymmetric encryption and digital signatures at the 256-bit security level. 
The algorithms used in this project are SHA-3 derived function KMACXOF256, and ECDHIES encryption and Schnorr signatures. 

# Services of the application
The project is divided into two parts. 
Part one (services 1 - 5): Symmetric cryptography uses the algorithm 'SHA-3 derived function KMACXOF256.' 
And part two (services 6 - 12): Elliptic curve arithmetic uses the algorithm 'ECDHIES encryption and Schnorr signatures.'

# The application offers 12 services:
1. Compute a plain cryptographic hash of a given file
2. Compute a plain cryptographic hash of input text: Extra Credit
3. Encrypt a given file symmetrically under a given passphrase
4. Decrypt a given file symmetrically under a given passphrase
5. Compute an authentication tag (MAC) of a given file under a given passphrase: Extra Credit
6. Generate an elliptic key pair file from a given passphrase
7. Encrypt a data file under a given elliptic public key file
8. Decrypt a given elliptic-encrypted file from a given password
9. Encrypt text input under a given elliptic public key: Extra Credit
10. Decrypt an elliptic-encrypted text input from a given password: Extra Credit
11. Sign a given file from a given password
12. Verify a given data file and its signature file under a given public key file

# The project includes five Java Source files:
1. KMACXOF256.java
    The KMACXOF256.java contains KMACXOF256, cSHAKE256, and all supporting functions bytepad, encode_string, left_encode, right_encode, and the Keccak core algorithm itself, following the NIST Special Publication 800-185 and Markku-Juhani O. Saarinin's sha3.c implementation from the GitHub link. We used byte arrays for most method parameters due to the specification taking byte arrays as input.
2. Sha3.java
    The Sha3.java contains Java Implementation of SHA3 from the reference; SHA3 Implementation by Markku-Juhani: https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
3. EllipticCurve.java
    The EllipticCurve.java contains the implementation of an elliptic curve known as  the E251 curve  (a  so-called Edwards curve). For our implementation, we used BigInteger due to the fact that regular integers were too small, and the division operation using BigInteger is more efficient than using normal division.
4. Application.java
    The Application.java contains the implementation of all 12 application services. During the project, we added more methods to Application.java in order to handle each service that was required.
5. AppLauncher.java
    The AppLauncher.java is used to run the application.
