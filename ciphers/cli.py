import argparse
import sys

def reverse(text: str):
    return text[::-1]

def removeDuplicates(text: str):
    return ''.join(dict.fromkeys(text))

def vigenereTR(text: str, key: str, alpha: str = ''):
    if alpha.isalpha():
        alpha = removeDuplicates(alpha)
    alphabet = 'აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ'
    alphabet = removeDuplicates(alpha + alphabet)

    tabula_recta = []
    for letter in alphabet:
        row = alphabet[alphabet.find(letter):] + alphabet[:alphabet.find(letter)]
        tabula_recta.append(row)

    new_key = ''
    i = 0
    for letter in text:
        if not letter.isalpha():
            new_key += letter
        else:
            new_key += key[i % len(key)]
            i += 1

    encrypted = ''
    for i in range(len(text)):
        if not text[i].isalpha():
            encrypted += text[i]
        else:
            encrypted += tabula_recta[
                alphabet.find(text[i])
            ][alphabet.find(new_key[i])]
    return encrypted

def vigenere(text, key):
    alphabet = 'აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ'
    new_key = ''
    i = 0
    for letter in text:
        if not letter.isalpha():
            new_key += letter
        else:
            new_key += key[i % len(key)]
            i += 1

    encrypted = ''
    for i in range(len(text)):
        if not text[i].isalpha():
            encrypted += text[i]
        else:
            encrypted += alphabet[
                (alphabet.find(text[i]) + alphabet.find(new_key[i]))
                % len(alphabet)
            ]
    return encrypted

def vigenereUpper(text, key):
    alphabet = 'ᲐᲑᲒᲓᲔᲕᲖᲗᲘᲙᲚᲛᲜᲝᲞᲟᲠᲡᲢᲣᲤᲥᲦᲧᲨᲩᲪᲫᲬᲭᲮᲯᲰ'
    text = text.upper()

    new_key = ''
    i = 0
    for letter in text:
        if not letter.isalpha():
            new_key += letter
        else:
            new_key += key[i % len(key)]
            i += 1

    encrypted = ''
    for i in range(len(text)):
        if not text[i].isalpha():
            encrypted += text[i]
        else:
            encrypted += alphabet[
                (alphabet.find(text[i]) + alphabet.find(new_key[i].upper()))
                % len(alphabet)
            ]
    return encrypted

def vigenereDecipher(text, key):
    alphabet = 'აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ'
    new_key = ''
    i = 0
    for letter in text:
        if not letter.isalpha():
            new_key += letter
        else:
            new_key += key[i % len(key)]
            i += 1

    decrypted = ''
    for i in range(len(text)):
        if not text[i].isalpha():
            decrypted += text[i]
        else:
            decrypted += alphabet[
                (alphabet.find(text[i]) - alphabet.find(new_key[i]))
                % len(alphabet)
            ]
    return decrypted

def caesar(text, shift):
    alphabet = 'აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ'
    shift %= len(alphabet)

    result = ""
    for char in text:
        if char in alphabet:
            idx = alphabet.index(char)
            result += alphabet[(idx + shift) % len(alphabet)]
        else:
            result += char
    return result

def caesarDecrypt(text, shift):
    return caesar(text, -shift)

def caesarBruteforce(text):
    for i in range(1, 26):
        print(f"{i}. {caesarDecrypt(text, i)}")

# ================= CLI =================

def main():
    parser = argparse.ArgumentParser(
        prog="kryptos",
        description="Georgian cipher command-line tool"
    )

    sub = parser.add_subparsers(dest="cipher")

    caesar_p = sub.add_parser("caesar")
    caesar_p.add_argument("mode", nargs="?", default="e")
    caesar_p.add_argument("text")
    caesar_p.add_argument("shift", nargs="?", type=int)
    caesar_p.add_argument("-b", "--bruteforce", action="store_true")

    vig_p = sub.add_parser("vigenere")
    vig_p.add_argument("mode", nargs="?", default="e")
    vig_p.add_argument("text")
    vig_p.add_argument("key")

    args = parser.parse_args()

    if args.cipher == "caesar":
        if args.bruteforce:
            caesarBruteforce(args.text)
            return

        if args.shift is None:
            print("Shift required")
            sys.exit(1)

        if args.mode == "d":
            print(caesarDecrypt(args.text, args.shift))
        else:
            print(caesar(args.text, args.shift))

    elif args.cipher == "vigenere":
        if args.mode == "d":
            print(vigenereDecipher(args.text, args.key))
        else:
            print(vigenere(args.text, args.key))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

