from Crypto.Cipher import AES
WB_KEY = b"r2p4y1sN0wSecur3"

cipher = AES.new(WB_KEY, AES.MODE_ECB)
output = cipher.decrypt(bytes.fromhex("9497cdf1df2600e7f63778d0ae91dcbb"))
print(output.decode())
