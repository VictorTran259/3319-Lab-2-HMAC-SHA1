import struct

# n = a 32 bit integer to be left-shifted
# b = the number of bits that n will be shifted to the left
def leftrotate(n, b):
    # Left-shift integer n by b bits and wrap around to the right
    return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

# This code is based on the pseudocode provided in the SHA1.md file
# message = the message that will be put through SHA1
def sha1(message):
    # Initialize variables
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    ml = len(message) * 8  # Message length in bits

    # Pre-processing: append the bit '1' to the message e.g. by adding 0x80 if message length is a multiple of 8 bits
    message += b'\x80'

    # Append 0 ≤ k < 512 bits '0', such that the resulting message length in bits is congruent to −64 ≡ 448 (mod 512)
    while len(message) % 64 != 56:
        message += b'\x00'

    # Append ml, the original message length in bits, as a 64-bit big-endian integer. Thus, the total length is a multiple of 512 bits
    message += struct.pack('>Q', ml)

    # Process the message in 512-bit blocks
    for i in range(0, len(message), 64):
        chunk = message[i:i + 64]

        # Break the chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        words = list(struct.unpack('>16I', chunk))

        # Extend the sixteen 32-bit words into eighty 32-bit words
        for j in range(16, 80):
            words.append(leftrotate(words[j - 3] ^ words[j - 8] ^ words[j - 14] ^ words[j - 16], 1))

        # Initialize hash value for this chunk
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        # Main loop
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (leftrotate(a, 5) + f + e + k + words[i]) & 0xFFFFFFFF
            e = d
            d = c
            c = leftrotate(b, 30)
            b = a
            a = temp

            # Print the values of h0, h1, h2, h3, and h4 after each round of SHA1
            # Uncomment this print statment below for testing purposes
            #print(f"Round {i}: h0={a:08x}, h1={b:08x}, h2={c:08x}, h3={d:08x}, h4={e:08x}")

        # Add this chunk's hash to result so far:
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    # Produce the final hash value (big-endian) as a 160-bit number
    hh = ((h0 << 128) | (h1 << 96) | (h2 << 64) | (h3 << 32) | h4)

    # Convert the 160-bit hash to a hexadecimal string representation
    sha1_hex_string = format(hh, '040x')
    return sha1_hex_string

# Test case for this SHA-1 implementation
# Uncomment this code below to test this SHA1 implementation on the message 'abc'
#message = b'abc'
#sha1_hash = sha1(message)
#print("Calculated HMAC Value:", sha1_hash)
