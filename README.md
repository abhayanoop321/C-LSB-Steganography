# LSB Steganography

# Description
A command-line tool developed in C to hide secret data within BMP image files using the Least Significant Bit (LSB) technique. This project demonstrates how to manipulate image metadata and pixel data to achieve data concealment without noticeably altering the visual quality of the image.

# Features
- Encoding : Embeds a secret text file into a '.bmp' source image.
- Decoding : Extracts hidden files from a stego-image.
- Security : Implements a "Magic String" verification to ensure only valid stego-files are processed.
- Robustness : Handles file extension and size metadata dynamically to ensure the secret file is reconstructed perfectly.

# Technical Skills
- File I/O operations in C
- Bitwise manipulation
- BMP File Structure (Header and Pixel array analysis)
- Command-line argument processing
