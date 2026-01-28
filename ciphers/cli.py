import argparse
import sys

GE_ALPHABET = "აბგდევზთიკლმნოპჟრსტუფქღყშჩცძწჭხჯჰ"
EN_ALPHABET = "abcdefghijklmnopqrstuvwxyz"

def reverse(text: str):
    return text[::-1]

def removeDuplicates(text: str):
    return ''.join(dict.fromkeys(text))

def tabulaRecta(alphabet: str, alpha: str):
    if alpha.isalpha():
        alpha = removeDuplicates(alpha)
    alphabet = removeDuplicates(alpha + alphabet)

    tabula_recta = []
    for letter in alphabet:
        row = alphabet[alphabet.find(letter):] + alphabet[:alphabet.find(letter)]
        tabula_recta.append(row)

    return tabula_recta

def printTabulaRecta(table: list[str]):
    alphabet = table[0]

    print("  " + " ".join(alphabet))
    for i, row in enumerate(table):
        print(alphabet[i] + " " + " ".join(row))

def vigenere(text: str, key: str):
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
    for i in range(1, 33):
        print(f"{i}. {caesarDecrypt(text, i)}")

# ================= CLI =================

def kryptos():
    parser = argparse.ArgumentParser(
        prog="kryptos",
        description="Georgian cipher command-line tool",
    )

    sub = parser.add_subparsers(dest="cipher", required=True)

    # ---- Caesar ----
    caesar_p = sub.add_parser("caesar", help="Caesar cipher")
    caesar_mode = caesar_p.add_mutually_exclusive_group(required=False)
    caesar_mode.add_argument("-e", "--encrypt", action="store_true", help="Encrypt")
    caesar_mode.add_argument("-d", "--decrypt", action="store_true", help="Decrypt")

    caesar_p.add_argument("-b", "--bruteforce", action="store_true", help="Bruteforce all shifts")
    caesar_p.add_argument("text", help="Input text")
    caesar_p.add_argument("shift", nargs="?", type=int, help="Shift (integer)")

    # ---- Vigenere ----
    vig_p = sub.add_parser("vigenere", help="Vigenere cipher")
    vig_mode = vig_p.add_mutually_exclusive_group(required=True)
    vig_mode.add_argument("-e", "--encrypt", action="store_true", help="Encrypt")
    vig_mode.add_argument("-d", "--decrypt", action="store_true", help="Decrypt")

    vig_p.add_argument("text", help="Input text")
    vig_p.add_argument("key", help="Key")

    # ---- Tabula Recta ----
    tr_p = sub.add_parser("tabula-recta", help="Generate Tabula Recta")
    tr_p.add_argument("lang", help="Language code (ge, en)")
    tr_p.add_argument("keyword", help="Keyword")

    args = parser.parse_args()

    # ---------- Caesar ----------
    if args.cipher == "caesar":
        if args.bruteforce:
            caesarBruteforce(args.text)
            return

        if not (args.encrypt or args.decrypt):
            print("Mode required: -e or -d")
            sys.exit(1)

        if args.shift is None:
            print("Shift required")
            sys.exit(1)

        if args.decrypt:
            print(caesarDecrypt(args.text, args.shift))
        else:
            print(caesar(args.text, args.shift))

    # ---------- Vigenere ----------
    elif args.cipher == "vigenere":
        if args.decrypt:
            print(vigenereDecipher(args.text, args.key))
        else:
            print(vigenere(args.text, args.key))

    # ---------- Tabula Recta ----------
    elif args.cipher == "tabula-recta":
        alphabets = {
            "ge": GE_ALPHABET,
            "en": EN_ALPHABET,
        }

        base = alphabets.get(args.lang.lower())
        if not base:
            print(f"Unknown language: {args.lang}")
            sys.exit(1)

        table = tabulaRecta(base, args.keyword)

        print("\nTabula Recta:\n")
        printTabulaRecta(table)
    else:
        parser.print_help()


if __name__ == "__main__":
    kryptos()

