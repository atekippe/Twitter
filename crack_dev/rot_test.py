import enchant

def rot_decode(story, shift):
    #  https://stackoverflow.com/questions/8886947/caesar-cipher-function-in-python
    return ''.join([  # concentrate list to string
            (lambda c, is_upper: c.upper() if is_upper else c)  # if original char is upper case than convert result to upper case too
                (
                  ("abcdefghijklmnopqrstuvwxyz"*2)[ord(char.lower()) - ord('a') + shift % 26],  # rotate char, this is extra easy since Python accepts list indexs below 0
                  char.isupper()
                )
            if char.isalpha() else char  # if not in alphabet then don't change it
            for char in story
        ])

"""
ldrnogxkkhb - MESOPHYLLIC
ryhuforjjhg - OVERCLOGGED
19q8y9Pf5b-34Nncvr7b5uo=
veptlih - RALPHED
wbpanbneajz - AFTERFRIEND
bxmsgqxqee - PLAGUELESS
"epxivrexsv'w"
"""

data = "bxmsgqxqee"

i = 0
pwl = enchant.request_pwl_dict("words.txt")
d = enchant.DictWithPWL("en_US", "words.txt")



while i < 26:

    decoded = rot_decode(data, i)
    is_english = d.check(decoded)
    print(decoded)
    if is_english is True:
        print(decoded, is_english)
        break
    else:
        i += 1
