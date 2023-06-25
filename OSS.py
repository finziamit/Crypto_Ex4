import random
import math
from hashlib import sha256
from modular_funcs import *
import sys
from os import urandom

class OSSGenerator:
    '''
        Generates private and public keys for Ong-Schnorr-Shamir digital signature process
    '''
    def __init__(self, n):
        '''
        int n - size for a large odd nubmer in bytes
        '''
        self.__n_size = n
        self.__n = int.from_bytes(urandom(self.__n_size), 'big')
        if not self.__n % 2: self.__n+=1
        self.__generate_keys()

    def __generate_keys(self):        
        k = random.SystemRandom().randint(0, self.__n)
        while not math.gcd(self.__n, k) == 1:
            k = random.SystemRandom().randint(0, self.__n)

        g = (-1*(pow(inverse(k, self.__n), 2, self.__n))) % self.__n # computes g = (-(k^-1)^2) % n

        self.__public_key = (self.__n, g)
        self.__private_key = (self.__n, k)

    @property
    def get_public_key(self):
        return self.__public_key

    @property
    def get_private_key(self):
        return self.__private_key


class OSSPubKey:
    def __init__(self, n, g):
        '''
        int n - large odd number
        ing g - based on a calculation of n and random int k
        '''
        self.__n = n
        self.__g = g
    
    def ver(self, M, sig):
        '''
        bytes M - document in bytes
        tuple [int, int] sig - sig(M) = (S1, S2)
        '''
        h_M = int.from_bytes(sha256(M).digest(), 'big')
        print(f"S1: {sig[0]} \n S2: {sig[1]} \n n: {self.__n} \n g: {self.__g} \n h(M): {h_M}") # test the variables values
        return (pow(sig[0], 2, self.__n) + (self.__g*pow(sig[1], 2, self.__n))) % self.__n == (h_M % self.__n)


class OSSPriKey:
    def __init__(self, n, k):
        '''
        int n - large odd number
        ing k - a random int for which gcd(n, k) = 1
        '''
        self.__n = n
        self.__k = k
    
    def sig(self, M):
        '''
        bytes M - a document to be signed
        '''
        r = random.SystemRandom().randint(0, self.__n)
        while not math.gcd(self.__n, r) == 1:
            r = random.SystemRandom().randint(0, self.__n)

        h_M = int.from_bytes(sha256(M).digest(), 'big')
        S1 = (inverse(2, self.__n) * (h_M * inverse(r, self.__n) + r)) % self.__n
        S2 = (inverse(2, self.__n) * self.__k * (h_M * inverse(r, self.__n) - r)) % self.__n
        print(f"S1: {S1} \n S2: {S2} \n n: {self.__n} \n k: {self.__k} \n h(M): {h_M}") # test the variables values
        return S1,S2


def generate_keys():
    '''
    generate OSS private and public keys to public.key and private.key files
    '''
    key_size = int(input("Enter the size of the key please: "))
    gen = OSSGenerator(key_size)    
    n, k = gen.get_private_key
    n = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    size_n = len(n).to_bytes(2, 'big')
    k = k.to_bytes((k.bit_length() + 7) // 8, 'big')
    with open('private.key', 'wb') as f:
        f.write(size_n)
        f.write(n)
        f.write(k)

    n, g = gen.get_public_key
    n = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    size_n = len(n).to_bytes(2, 'big')
    g = g.to_bytes((g.bit_length() + 7) // 8, 'big')
    with open('public.key', 'wb') as f:
        f.write(size_n)
        f.write(n)
        f.write(g)


def sig_doc():
    '''
    sign a document and save it with postfix .sig
    '''
    filename = input("Enter file's name (without extention): ")
    with open(filename+'.txt', 'rb') as f:
        M = f.read()
    with open('private.key', 'rb') as f:
        pr_key = f.read()
    size_n = int.from_bytes(pr_key[:2], 'big')
    n_stopper = 2+size_n
    n = int.from_bytes(pr_key[2:n_stopper], 'big')
    k = int.from_bytes(pr_key[n_stopper+2:], 'big')
    oss_pr_key = OSSPriKey(n, k)
    S1, S2 = oss_pr_key.sig(M)
    S1 = S1.to_bytes((S1.bit_length() + 7) // 8, 'big')
    S2 = S2.to_bytes((S2.bit_length() + 7) // 8, 'big')
    size_S1 = len(S1).to_bytes(2, 'big')
    size_S2 = len(S2).to_bytes(2, 'big')
    with open(filename+'.sig', 'wb') as f:
        f.write(size_S1)
        f.write(S1)
        f.write(size_S2)
        f.write(S2)
        f.write(M)


def ver_doc():
    '''
    verify if a document signature
    '''
    filename = input("Enter file's name (without extention): ")
    with open(filename+'.sig', 'rb') as f:
        M = f.read()
    with open('public.key', 'rb') as f:
        pu_key = f.read()
    size_n = int.from_bytes(pu_key[:2], 'big')
    n_stopper = 2+size_n
    n = int.from_bytes(pu_key[2:n_stopper], 'big')
    g = int.from_bytes(pu_key[n_stopper+2:], 'big')
    oss_pu_key = OSSPubKey(n, g)

    size_S1 = int.from_bytes(M[:2], 'big')
    S1_stopper = 2+size_S1
    S1 = int.from_bytes(M[2:S1_stopper], 'big')
    size_S2 = int.from_bytes(M[S1_stopper:S1_stopper+2], 'big')
    S2_stopper = S1_stopper+2+size_S2
    S2 = int.from_bytes(M[S1_stopper+2:S2_stopper], 'big')
    data = M[S2_stopper:]

    res = 'valid' if oss_pu_key.ver(data, (S1, S2)) else 'invalid'
    print(f'The signature is {res}')


def main():
    choice = input("Enter the nubmer of your choice\n(1) Generate encryption keys\n(2) Sign a document\n(3) Verify signature\n->")
    if choice == '1':
        generate_keys()
    elif choice == '2':
        sig_doc()
    elif choice == '3':
        ver_doc()
    else:
        print("Bye Bye")
        sys.exit()


if __name__ == '__main__':
    main()
