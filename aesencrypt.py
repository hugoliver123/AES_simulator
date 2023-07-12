
nK = 4


def printMatrixHex(arr):  # methods for test, Not used for result
    print("Start of matrix output:")
    try:
        for i in range(len(arr)):
            for j in range(len(arr[i])):
                print(hex(arr[i][j]), end=" ")
            print("")
    except:
        for i in range(len(arr)):
            print(hex(arr[i]), end=" ")
    print(" ")
    return None


def transpose(matrix):  # Matrix transpose
    return [[row[i] for row in matrix] for i in range(len(matrix[0]))]


def flatten(multi_list):  # Matrix flatten for output stream
    f_list = []
    for i in multi_list:
        if isinstance(i, list):
            f_list.extend(flatten(i))
        else:
            f_list.append(i)
    return f_list


def matrix_xor(str, key):  # calculate two 4*4 matrix XOR
    for i in {0, 1, 2, 3}:
        for j in {0, 1, 2, 3}:
            str[i][j] = str[i][j] ^ key[i][j]
    return str


# sub bytes
sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]


def single_subBytes(a):  # Sub-byte for single byte
    sixteen = int(a / 16)
    rest = a % 16
    return sbox[sixteen * 16 + rest]


def matrix_subBytes(matrix):  # Sub-byte for total matrix (block) 16 bytes
    for i in {0, 1, 2, 3}:
        for j in {0, 1, 2, 3}:
            matrix[i][j] = single_subBytes(matrix[i][j])
    return matrix


# shift rows
def shift_rows(data):
    for i in {1, 2, 3}:
        data[i][:] = data[i][i:] + data[i][:i]
    return data


# mix columns
def gf_mul(a, b):  # Calculate multiple in GF(2^8)
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a <<= 1
        if high_bit:
            a ^= 0x1b
        b >>= 1
    return result


def of_down(hexNum):  # Calculate result may over 0xff
    if hexNum > 0xff:
        hexNum = hexNum - 0x100
    return hexNum


def mix_columns(matrix):  # Mix columns
    matrix = transpose(matrix)
    matrix_ret = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]

    for i in {0, 1, 2, 3}:
        # Mix columns for each columns
        matrix_ret[i][0] = of_down(
            (gf_mul(0x02, matrix[i][0]) ^ gf_mul(0x03, matrix[i][1]) ^ gf_mul(0x01, matrix[i][2]) ^ gf_mul(0x01,
                                                                                                           matrix[i][
                                                                                                               3]))
        )
        matrix_ret[i][1] = of_down(
            (gf_mul(0x01, matrix[i][0]) ^ gf_mul(0x02, matrix[i][1]) ^ gf_mul(0x03, matrix[i][2]) ^ gf_mul(0x01,
                                                                                                           matrix[i][
                                                                                                               3]))
        )
        matrix_ret[i][2] = of_down(
            (gf_mul(0x01, matrix[i][0]) ^ gf_mul(0x01, matrix[i][1]) ^ gf_mul(0x02, matrix[i][2]) ^ gf_mul(0x03,
                                                                                                           matrix[i][
                                                                                                               3]))
        )
        matrix_ret[i][3] = of_down(
            (gf_mul(0x03, matrix[i][0]) ^ gf_mul(0x01, matrix[i][1]) ^ gf_mul(0x01, matrix[i][2]) ^ gf_mul(0x02,
                                                                                                           matrix[i][
                                                                                                               3]))
        )

    return transpose(matrix_ret)


# round key Input add
rcon = [
    [0x01, 0x00, 0x00, 0x00], [0x02, 0x00, 0x00, 0x00], [0x04, 0x00, 0x00, 0x00], [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00], [0x20, 0x00, 0x00, 0x00], [0x40, 0x00, 0x00, 0x00], [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00], [0x36, 0x00, 0x00, 0x00]
]


def key_xor(a, b):
    for i in {0, 1, 2, 3}:
        a[i] = a[i] ^ b[i]
    return a


# Key and Round Key Generator
def round_key_generator(keyInput):
    tKey = list(keyInput)           # total round KEY
    for index in range(44 - nK):
        if len(tKey) % 4 == 0:
            temp = list(tKey[-1])
            temp[:] = temp[1:] + temp[:1]
            temp = [single_subBytes(byte) for byte in temp]
            temp = key_xor(temp, rcon[len(tKey) // nK - 1])
            temp = key_xor(temp, tKey[len(tKey) - nK])
        else:
            temp = key_xor(list(tKey[-1]), tKey[len(tKey) - nK])

        tKey.append(temp)

    return tKey


def key_organizer(text):
    if len(text) == 16:  # Convert Key String to list and check if key sting has correct length
        block4 = [text[i:i + 4] for i in range(0, len(text), 4)]
        return block4
    else:
        return ('Key length error')


# AES block encrypt method, PKCS7 padding
def padding_and_split(text):  # PKCS7 padding and split to 16 bytes per block
    paddingLen = 16 - len(text) % 16
    if paddingLen != 16:
        for i in range(paddingLen):
            text.append(int(paddingLen))
    step = 16
    block16 = [text[i:i + step] for i in range(0, len(text), step)]
    return block16


def block_str_ord(setChar):  # Block string order. Covert to 4*4 matrix and check data type
    if len(setChar) == 16:
        for num in range(len(setChar)):
            if type(setChar[num]) == type('a'):
                setChar[num] = ord(setChar[num])

        inputStr = [[setChar[i] for i in range(4)], [setChar[i] for i in range(4, 8)],
                    [setChar[i] for i in range(8, 12)], [setChar[i] for i in range(12, 16)]]

        return inputStr
    else:
        print("block not 16 chars, cannot ORD")


def aes_block_en(inputStr, set_Key):  # AES encryption
    inputStr = transpose(inputStr)

    # Round zero
    inputStr = matrix_xor(inputStr, transpose([set_Key[0], set_Key[1], set_Key[2], set_Key[3]]))

    # Main 10 Round
    for index in range(1, 10):
        # sub bytes
        inputStr = matrix_subBytes(inputStr)
        # Shift row
        inputStr = shift_rows(inputStr)
        # Mix Columns
        inputStr = mix_columns(inputStr)
        # Round Key ADD
        inputStr = matrix_xor(inputStr, transpose([set_Key[int(index * nK)], set_Key[int(index * nK + 1)],
                                                   set_Key[int(index * nK + 2)], set_Key[int(index * nK + 3)]]))

    # last Round
    inputStr = matrix_subBytes(inputStr)
    inputStr = shift_rows(inputStr)
    inputStr = matrix_xor(inputStr, transpose([set_Key[-4], set_Key[-3], set_Key[-2], set_Key[-1]]))

    return inputStr


def aes_en_gate(plaintext, key):
    text16 = padding_and_split(list(plaintext))

    # Key example:
    # key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
    input_key = key_organizer(key)
    round_keys = round_key_generator(input_key)  # Generating ALL Round Key

    cipher_blocks = []
    for block in text16:
        input_str = block_str_ord(block)
        output_str = transpose(aes_block_en(input_str, round_keys))
        cipher_blocks.append(output_str)
    cipher = flatten(cipher_blocks)
    return cipher
