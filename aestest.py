import os
import sys

import aesdecrypt
import aesencrypt


def input_check(text):
    print("Your input length:", end=" ")
    print(len(text))
    for char in text:
        if ord(char) > 127:
            return False
    return True


if __name__ == '__main__':
    # plaintext = "We hold these truths to be self-evident, that all men are created equal, that they are endowed by their Creator with certain unalienable Rights, that among these are Life, Liberty and the pursuit of Happiness.--That to secure these rights, Governments are instituted among Men, deriving their just powers from the consent of the governed, --That whenever any Form of Government becomes destructive of these ends, it is the Right of the People to alter or to abolish it, and to institute new Government, laying its foundation on such principles and organizing its powers in such form, as to them shall seem most likely to effect their Safety and Happiness. Prudence, indeed, will dictate that Governments long established should not be changed for light and transient causes; and accordingly all experience hath shewn, that mankind are more disposed to suffer, while evils are sufferable, than to right themselves by abolishing the forms to which they are accustomed. But when a long train of abuses and usurpations, pursuing invariably the same Object evinces a design to reduce them under absolute Despotism, it is their right, it is their duty, to throw off such Government, and to provide new Guards for their future security.--Such has been the patient sufferance of these Colonies; and such is now the necessity which constrains them to alter their former Systems of Government. The history of the present King of Great Britain is a history of repeated injuries and usurpations, all having in direct object the establishment of an absolute Tyranny over these States. To prove this, let Facts be submitted to a candid world."
    # plaintext = "0123456789abcdefdeki"

    plaintext = input("Please input your plaintext end with Enter, MUST ASCII CODE CHAR\n")  # text input
    if not input_check(list(plaintext)):  # Input CHAR check
        print("Your input contain non-ASCII char, system end")
        sys.exit()

    print("___________________________AES Start______________________________________")
    key = list(os.urandom(16))  # Key Generating
    ciphertext = aesencrypt.aes_en_gate(plaintext, key)  # Call AES Encrypt

    print("KEY:")  # HEX prints of cipher and key for human reading
    for i in key:
        print(hex(i), end=" ")
    print(("\n\nCIPHER:"))
    for i in ciphertext:
        print(hex(i), end=" ")

    decryption = aesdecrypt.aes_de_gate(ciphertext, key)  # Call AES Decrypt
    out_strings = ""  # Output String
    print("\n\nDECRYPTED:")
    for i in decryption:
        out_strings += chr(i)
    print(out_strings)  # HEX to English

    print("\nIS SAME AS INPUTTED PLAINTEXT?  ", end=" ")
    print(out_strings == plaintext)  # quality Control
