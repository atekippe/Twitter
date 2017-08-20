import binascii


def binary_decode(binary_data):

    hex_bin = hex(int((binary_data[2:]), 2))
    decoded_binary = (binascii.unhexlify(hex_bin[2:]))
    return decoded_binary.decode("utf-8")

#[bin(int(binascii.hexlify(string), 16)), ""]
binary = '0b110011001110010011101010110100101110100011001110111001001101111011101110110010101110010'
test2 = '0b110010001101001011100100111010000101101011000100110010101110011011011010110010101100001011100100110010101100100'
print(binary_decode(test2))



"""
string = "TEST"

hexLify = binascii.hexlify(b'string')
print(hexLify)
intLify = int(hexLify, 16)
print(intLify)

print(bin(intLify))
"""