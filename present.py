#!/bin/python3
from itertools import repeat
# rotation
def rotate(input,d):
   # Slice string in two parts for left and right
   Lfirst = input[0 : d]
   Lsecond = input[d :]
   Rfirst = input[0 : len(input)-d]
   Rsecond = input[len(input)-d : ]
   return (Lsecond + Lfirst)

def encrypt(key,plain):
    # KEY : to hex
    assert  isinstance(key,str)
    assert  isinstance(plain,str)
    key = bin(int(key,16)).replace('0b','').zfill(80)
    key_binary = key.encode(encoding='utf_8')
    hex_key = key_binary.hex()

    # Code to convert hex to binary
    res = "{0:08b}".format(int(key, 16))
    # KEY : to bits
    bin_key = ''.join(format(ord(i), 'b') for i in key)

    # PLAIN : to Hex
    plain = bin(int(plain,16)).replace('0b','').zfill(64)
    plain_binary = plain.encode(encoding='utf_8')
    bin_plain = ''.join(format(ord(i), 'b') for i in plain)

    # SBOX
    sbox_dict={'0' : 'c', '1': '5','2' :'6','3' :'b','4': '9','5':'0','6':'a','7':'d','8':'3','9':'e','a':'f','b':'8','c':'4','d':'7','e' :'1','f':'2'}
    sbox_str='c 5 6 b 9 0 a d 3 e f 8 4 7 1 2'
    sbox_list= sbox_str.split(' ')

    # PBOX
    pbox_str = '0 16 32 48 1 17 33 49 2 18 34 50 3 19 35 51 4 20 36 52 5 21 37 53 6 22 38 54 7 23 39 55 8 24 40 56 9 25 41 57 10 26 42 58 11 27 43 59 12 28 44 60 13 29 45 61 14 30 46 62 15 31 47 63'
    pbox_list=pbox_str.split(' ')

    # Rotate key
    roundkeys = []
    salt_list = []
    for round in range(0,32):
        if round==0:
            #register=rotate(key,61)
            register = key[:80]
            round_key = key[:16]
            roundkeys.append(round_key)

            salt = ''.join(register[64:])
            salt = hex(int(salt, 2))
            salt_list.append(salt)

        else:
            register=rotate(register,61)
            # Sbox operation
            first_key_bits = int(register[0:4],2)
            if ord(sbox_list[first_key_bits]) > 57:
                sbox_res = "{0:04b}".format(int(sbox_list[first_key_bits], 16))
            else :
                sbox_res = bin(int(sbox_list[first_key_bits]))
            sbox_res=(sbox_res.replace('0b',''))
            if len(sbox_res) < 4:
                sbox_res = sbox_res.zfill(4)

            register_list = list(register)
            for i in range(0,4):
                register_list.pop(0)

            for i in range(0,4):
                register_list.insert(0,sbox_res[len(sbox_res)-1-i])

            # round counter addition
            # k38 ... 34 xor counter
            counter_bits = ""
            for i in range(60,65):
                counter_bits += register_list[i]
            u = str(bin(int(counter_bits,2) ^ round))
            u=u.replace('0b','')
            if len(u) < 5 :
                u=u.zfill(5)
            register_list = register_list[0:60] + list(u) + register_list[65:]
            register = ''.join(register_list)
            round_key = ''.join(register_list[:64])
            round_key_hex = hex(int(round_key,2))
            round_key = round_key_hex.replace('0x','')
            if len(round_key) < 16:
                round_key = round_key.zfill(16)
            roundkeys.append(round_key)
            # get salt
            salt = ''.join(register_list[64:])

            
            salt_list.append(salt)

    state_list = []

    sbox_res=''
    for round in range (0,31):
        #res = bin(int(plain, 16))[2:].zfill(16)
        if round == 0 :
            plain_bin = bin(int(plain, 16))[2:].zfill(64)
            roundkey_bin = bin(int(roundkeys[0], 16))[2:].zfill(64)
            state = (hex(int(plain_bin,2) ^ int(roundkey_bin,2)))
            state= state.replace('0x','').zfill(64)
            state_list.append(state)
        else:
            state = state.replace('0b', '')
            roundkey_bin = bin(int(roundkeys[round], 16))[2:].zfill(64)
            state = bin(int(state, 2) ^ int(roundkey_bin,2))

            state = state.replace('0b', '').zfill(64)


        state_after_sbox = ''
        while len(state) != 0:
            first_key_bits =int( state[:4],2)
            # Sbox operation
            if ord(sbox_list[first_key_bits]) > 57:
                sbox_res = "{0:04b}".format(int(sbox_list[first_key_bits], 16))
            else:
                sbox_res = bin(int(sbox_list[first_key_bits]))
            sbox_res = (sbox_res.replace('0b', ''))
            if len(sbox_res) < 4:
                sbox_res = sbox_res.zfill(4)
            state_after_sbox += sbox_res
            state = state[4:]
        # permutation :

        state_after_pbox = [[] for i in repeat(None, 64)]

        for bit in range(0,len(state_after_sbox)):
            temp=int(pbox_list[bit])
            state_after_pbox[temp]= state_after_sbox[bit]


        state = ''.join(state_after_pbox[:64])
        state_hex = hex(int(state,2))
        state_hex = state_hex.replace('0x', '')
        if len(state_hex) < 16:
            state_hex = state_hex.zfill(16)
        state_list.append(state_hex)

    result = hex(int(roundkeys[31], 16) ^ int(state_list[31], 16))
    return result



