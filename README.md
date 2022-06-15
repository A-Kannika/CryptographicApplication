# CryptographicApplication

## Introduction:
The Cryptographic Library & App is a project of TCSS 487 Cryptography course, in Spring 2022, 
at the University of Washington Tacoma. This project aims to implement (in Java) a library and an app 
for asymmetric encryption and digital signatures at the 256-bit security level. 
The algorithms used in this project are SHA-3 derived function KMACXOF256, and ECDHIES encryption and Schnorr signatures. 

## Services of the application
The project is divided into two parts. 
Part one (services 1 - 5): Symmetric cryptography uses the algorithm 'SHA-3 derived function KMACXOF256.' 
And part two (services 6 - 12): Elliptic curve arithmetic uses the algorithm 'ECDHIES encryption and Schnorr signatures.'

## The application offers 12 services:
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

## The project includes five Java Source files:
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

## Screenshots of the application services

### The main menu of the application

<img width="805" alt="Screen Shot 2022-06-02 at 10 57 27 PM" src="https://user-images.githubusercontent.com/49578771/173779244-883c63b2-7e68-4c6c-a8f0-718ec150d23b.png">

### 1. Compute a plain cryptographic hash of a given file 

<img width="875" alt="Screen Shot 2022-06-02 at 5 53 51 PM" src="https://user-images.githubusercontent.com/49578771/173778415-ef230e0d-d821-441c-9a3b-1622edf23edf.png">

### 2. Compute a plain cryptographic hash of input text: Extra Credit

<img width="1299" alt="Screen Shot 2022-06-02 at 5 58 40 PM" src="https://user-images.githubusercontent.com/49578771/173778441-7af7ef67-bcf1-4440-8f08-348544df43d4.png">

### 3. Encrypt a given file symmetrically under a given passphrase

<img width="892" alt="Screen Shot 2022-06-02 at 6 05 08 PM" src="https://user-images.githubusercontent.com/49578771/173778487-11731a60-de86-460a-8337-4619223ef84a.png">

### 4. Decrypt a given file symmetrically under a given passphrase

<img width="893" alt="Screen Shot 2022-06-02 at 6 12 38 PM" src="https://user-images.githubusercontent.com/49578771/173778545-9bdefc98-744c-416b-8ec3-194ddb8bf42f.png">

### 5. Compute an authentication tag (MAC) of a given file under a given passphrase: Extra Credit

<img width="855" alt="Screen Shot 2022-06-02 at 6 34 53 PM" src="https://user-images.githubusercontent.com/49578771/173778675-cc36f431-9c4a-4dd0-ac84-f94384f4e523.png">

## 6. Generate an elliptic key pair file from a given passphrase

<img width="861" alt="Screen Shot 2022-06-02 at 6 43 20 PM" src="https://user-images.githubusercontent.com/49578771/173778821-53e98720-e565-480d-bf80-df5a1d2c7458.png">

### 7. Encrypt a data file under a given elliptic public key file

<img width="909" alt="Screen Shot 2022-06-02 at 6 56 54 PM" src="https://user-images.githubusercontent.com/49578771/173778880-ec8bf683-d23f-422e-a1cf-67e694cdee86.png">

### 8. Decrypt a given elliptic-encrypted file from a given password

<img width="963" alt="Screen Shot 2022-06-02 at 7 09 14 PM" src="https://user-images.githubusercontent.com/49578771/173778909-f91d20be-1f0c-4f4f-b518-5c2916946f77.png">

### 9. Encrypt text input under a given elliptic public key: Extra Credit


<img width="1154" alt="Screen Shot 2022-06-02 at 10 58 41 PM" src="https://user-images.githubusercontent.com/49578771/173779051-6a3c14e2-7b56-4547-adbe-e4cdd974b77b.png">

### 10. Decrypt an elliptic-encrypted text input from a given password: Extra Credit

<img width="1173" alt="Screen Shot 2022-06-02 at 11 00 14 PM" src="https://user-images.githubusercontent.com/49578771/173779091-8ba5bfe8-8548-42f7-8947-6efd62defe38.png">

### 11. Sign a given file from a given password
 
<img width="883" alt="Screen Shot 2022-06-02 at 8 15 34 PM" src="https://user-images.githubusercontent.com/49578771/173779146-04d093da-4d27-4da0-a4c1-3c41e62778db.png">

### 12. Verify a given data file and its signature file under a given public key file

<img width="809" alt="Screen Shot 2022-06-02 at 8 17 04 PM" src="https://user-images.githubusercontent.com/49578771/173779156-4a03633c-adc0-41f8-8f73-328822cc8a0b.png">

### 13. Exit the application
<img width="802" alt="Screen Shot 2022-06-02 at 8 17 23 PM" src="https://user-images.githubusercontent.com/49578771/173779213-11278f31-d6fd-49ab-97af-bf659c5908a9.png">
