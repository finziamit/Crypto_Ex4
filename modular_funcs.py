# -*- coding: utf-8 -*-
"""
Created on Wed Dec 18 14:40:29 2019

@author: Dani
"""
import random

def inverse(x,n):
    ''' returns x^(-1) mod n '''
    s0 = 1; s1 = 0
    t0 = 0; t1 = 1
    r0 = n; r1 = x
    while r0%r1 != 0:
        q = r0//r1
        s0, s1 = s1, s0-q*s1
        t0, t1 = t1, t0-q*t1
        r0, r1 = r1, r0%r1
    if r1>1: return None
    return t1%n

def modular_power(a,b,n):
    """ computes a**b (mod n) using iterated squaring 
        assumes b is a nonnegative integer """
    binary_str=bin(b)[2:]
    result = 1
    for x in binary_str:
        result=(result**2)%n
        if x=='1':
            result=result*a%n            
    return result


def is_quad_res(a,p):
    return a==0 or modular_power(a,(p-1)//2,p) == 1


def modular_root(a,p):
    ''' computes sqrt(a) modulo p '''
    if a==0: return 0
    if not is_quad_res(a,p):
        return None
    n=2
    while is_quad_res(n,p):
        n+=1
    alpha = 1
    s=(p-1)//2
    j=0
    i=1
    while s%2==0:
        alpha+=1
        s//=2
    b=modular_power(n,s,p)
    r=modular_power(a,(s+1)//2,p)
    root=r
    power_2_check=modular_power(2,alpha-1,p)
    d=2
    a_inv=inverse(a,p)
    while d <= alpha:
        power_2_check //= 2
        test_val = modular_power(a_inv*root*root%p,power_2_check,p)
        if test_val != 1:
            j+=i
        i*=2
        root = modular_power(b,j,p)*r%p
        d+=1
    return random.choice([root, p-root])

def main():
    print(modular_root(21, 101))

    
if __name__ == '__main__':
    main()