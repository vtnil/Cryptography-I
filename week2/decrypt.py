# vtnil write for Cryptography1 week2 homework
# ppt https://crypto.stanford.edu/~dabo/cs255/lectures/PRP-PRF.pdf


from Crypto.Cipher import AES
from binascii import a2b_hex
from math import ceil



questions = [
    {"key": "140b41b22a29beb4061bda66b6747e14",
     "ct": "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"},
    {"key": "140b41b22a29beb4061bda66b6747e14",
     "ct": "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"},
    {"key": "36f18357be4dbd77f050515c73fcf9f2",
     "ct": "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"},
    {"key": "36f18357be4dbd77f050515c73fcf9f2",
     "ct": "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"},
]

BLOCK_SIZE = 16
MODEL_CBC = 'cbc'
MODEL_CTR = 'ctr'

AES.block_size = BLOCK_SIZE


def decrypt(question, mode):
    key = a2b_hex(question['key'])
    ctb = a2b_hex(question['ct'])
    iv = ctb[:BLOCK_SIZE]
    ct = ctb[BLOCK_SIZE:]
    plain = []

    cipher = AES.new(key)

    if mode == MODEL_CBC:
        _iv = iv
        for i in range(0, int(len(ct) / BLOCK_SIZE)):
            _b = ct[BLOCK_SIZE * i: BLOCK_SIZE * (i + 1)]
            _k = cipher.decrypt(_b)
            plain += [a ^ b for (a, b) in zip(_iv, _k)]
            _iv = _b

        # remove padding
        _len = plain[-1]
        if [_len] * _len == plain[-_len:]:
            plain = plain[:-_len]

    else:
        for i in range(0, ceil(len(ct) / BLOCK_SIZE)):
            # Be careful!!! Here is ENCRYPT!!
            _k = cipher.encrypt((int.from_bytes(iv, 'big') + i).to_bytes(BLOCK_SIZE, 'big'))
            _b = ct[BLOCK_SIZE * i: BLOCK_SIZE * (i + 1)]
            plain += [_k[i] ^ _b[i] for i in range(0, len(_b))]

    return ''.join([chr(a) for a in plain])


print(decrypt(questions[0], MODEL_CBC))
print(decrypt(questions[1], MODEL_CBC))
print(decrypt(questions[2], MODEL_CTR))
print(decrypt(questions[3], MODEL_CTR))
