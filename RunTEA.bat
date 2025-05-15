@echo off
:: Run the first compiled program
echo Running Encryption...
tea-cbc-enc TestFiles/IV.txt TestFiles/Key.txt TestFiles/Plaintext.txt TestFiles/Ciphertext.txt

:: Run the second compiled program
echo Running Decryption...
tea-cbc-dec TestFiles/IV.txt TestFiles/Key.txt TestFiles/Ciphertext.txt TestFiles/Plaintext1.txt
