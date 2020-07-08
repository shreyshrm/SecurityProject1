"""
ECE 458 Project 1
Skeleton solution file.

You need to assign values to variables, and implement two functions as part of your answers to this project
You are not allowed to call any DSA signature package.
You are allowed to define whatever subroutines you like to structure your code.
"""

import hashlib
import binascii
import math


"""
sha3_224_hex() is design to take a hexadecimal string as the input and compute it's sha3_224 hash value. 
You may call sha3_224_hex() in your project for both DSA signature and sha3_224 hash computation
Don't directly call hashlib.sha3_224() which only takes a character string (then encode the string to utf-8 format) as the input.
No prefix for the input string, and len(hexstr) is even
e.g.  sha3_224_hex("4c")
"""

def sha3_224_hex( hexstr ):
	if len(hexstr)%2 != 0:
		raise ValueError("Error: Length of hex string should be even")
	m = hashlib.sha3_224()
	data = binascii.a2b_hex(str(hexstr))
	m.update(data)
	return m.hexdigest()

def is_prime( num ):
	if num > 1: 
		for i in range(2, num):  
			if (num % i) == 0: 
				break
			else: 
				return True
	else: 
		return False

def sha3_224_hex_formatter( hexstr ):
	hexstr = str(hexstr)
	if len(hexstr) % 2 == 1:
		hexstr = "0" + str(hexstr)
	if hexstr[:2] == "0x":
		hexstr = hexstr[2:]
	return format(int(sha3_224_hex(hexstr), 16), '0224b')

def zero_padder( number, length ):
	strNumber = str(number)
	if len(strNumber) == length:
		return strNumber
	else:
		numZeroes = length - len(strNumber)
		zeroes = '0' * numZeroes
		return zeroes + strNumber
		
#--------------------------------------------------------------------------------

# Part 1:Copy and paste your parameters here
# p,q,g are DSA domain parameters, sk_i (secret keys),pk_i (public keys),k_i (random numbers) are used in each signature and verification
p=16158504202402426253991131950366800551482053399193655122805051657629706040252641329369229425927219006956473742476903978788728372679662561267749592756478584653187379668070077471640233053267867940899762269855538496229272646267260199331950754561826958115323964167572312112683234368745583189888499363692808195228055638616335542328241242316003188491076953028978519064222347878724668323621195651283341378845128401263313070932229612943555693076384094095923209888318983438374236756194589851339672873194326246553955090805398391550192769994438594243178242766618883803256121122147083299821412091095166213991439958926015606973543
q=13479974306915323548855049186344013292925286365246579443817723220231
g=9891663101749060596110525648800442312262047621700008710332290803354419734415239400374092972505760368555033978883727090878798786527869106102125568674515087767296064898813563305491697474743999164538645162593480340614583420272697669459439956057957775664653137969485217890077966731174553543597150973233536157598924038645446910353512441488171918287556367865699357854285249284142568915079933750257270947667792192723621634761458070065748588907955333315440434095504696037685941392628366404344728480845324408489345349308782555446303365930909965625721154544418491662738796491732039598162639642305389549083822675597763407558360

sk1=2468542399739511421394838793729552363452894737807372506581726105316
sk2=4076793088131067940843769680503085028876094841680801728246361894575
sk3=2102432530782212106665368459269441274133324919822720218167143524572

p_binary = bin(p)[2:]
p_digits = len(p_binary)
print('Number of bits in p: ', p_digits)
print('is_prime(p): ', is_prime(p))

q_binary = bin(q)[2:]
q_digits = len(q_binary)
print('Number of bits in q: ', q_digits)
print('is_prime(q): ', is_prime(q))

g_binary = bin(g)[2:]
g_digits = len(g_binary)
print('Number of bits in g: ', g_digits)

factor = (p-1) % q
print('factor: ', factor)

factor_g = pow(g,q,p)
print('g^q % p = ', factor_g, 'which is equal to 1')

factor_g_1 = pow(g,2,p)
print ('g^2 % p = ', factor_g_1, ' which is not equal to 1')

m = (q-1)//2
print('m = (q-1)/2 = ', m)

factor_g_2 = pow(g,m,p)
print ('g^m % p = ', factor_g_2, ' which is not equal to 1')


#--------------------------------------------------------------------------------

# Part 2:Assign values that you compute to those parameters as part of your answers to (a) (b) and (c)
# (a) list all prime factors of p-1, list 3 public keys pk_i's corresponding to sk_i's, those numbers should be decimal integers

pfactor1 = 2
print('pfactor1: ', pfactor1)

pfactor2 = q
print('pfactor2: ', pfactor2)

pfactor3 = (p-1)//(2*q)
print('pfactor3: ', pfactor3)
print('isprime: ', is_prime(pfactor3))

pk1 = pow(g, sk1, p)
print('pk1: ', pk1)
pk1_binary = bin(pk1)[2:]

pk2 = pow(g, sk2, p)
print('pk2: ', pk2)
pk2_binary = bin(pk2)[2:]

pk3 = pow(g, sk3, p)
print('pk3: ', pk3)
pk3_binary = bin(pk3)[2:]

# (b) Sig_sk1 and Sig_sk2, k_i is the random number used in signature. 
# u, v, w is the intermediate results when verifying Sig_sk1(m1)
# All variables should be decimal integers

# (b)(1)
tempK1 = sha3_224_hex_formatter("01")
k1 = int(tempK1, 2)
print('k1: ', k1)

pk1_binary = zero_padder(pk1_binary, 2048)
pk2_binary = zero_padder(pk2_binary, 2048)
m1 = pk1_binary + pk2_binary + '00000101'


def Sign( p, q, g, k, sk, Message ):
	r = pow(g, k, p) % q
	hOfM = sha3_224_hex_formatter(Message)
	hOfM_int = int(hOfM, 2)
	knegativeOne = pow(k, -1, q)
	s = (knegativeOne*(hOfM_int + (sk*r))) % q
	return r,s

r1, s1 = Sign(p, q, g, k1, sk1, m1)
print('r1: ', r1)
print('s1: ', s1)


# # (b)(2)

def Verify( p, q, g, pk, Message, r, s ):
	if r >= q or s >= q:
		return false
	hOfM = sha3_224_hex_formatter(Message)
	hOfM_int = int(hOfM, 2)
	w = pow(s, -1, q)
	print('w: ', w)
	u1 = (hOfM_int*w) % q
	print('u1: ', u1)
	u2 = (r*w) % q
	print('u2: ', u2)
	v = ((pow(g, u1, p)*pow(pk, u2, p)) % p) % q
	print('v: ', v)	
	print('r\': ', r)
	
	if r == v:
		return True
	else:   
		return False

verified = Verify(p, q, g, pk1, m1, r1, s1)
print('verified for user 1: ', verified)
print(' ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ USER #2 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
tempK2 = sha3_224_hex_formatter("02")
k2 = int(tempK2, 2)
print('k2: ', k2)

pk2_binary = zero_padder(pk2_binary, 2048)
pk3_binary = zero_padder(pk3_binary, 2048)
m2 = pk2_binary + pk3_binary + '00000100'

r2, s2 = Sign(p, q, g, k2, sk2, m2)
print('r2: ', r2)
print('s2: ', s2)

verified = Verify(p, q, g, pk2, m2, r2, s2)
print('verified for user 2: ', verified)

# part D:
hashAmnt0 = sha3_224_hex_formatter('05')
print('hashAmnt0: ', hashAmnt0)

nonce1 = 115499297 
nonce1 = bin(nonce1)[2:]
nonce1 = zero_padder(nonce1, 128)

preimage1 = hashAmnt0 + m1 + nonce1
print('Length of PreImage1: ', len(preimage1))
preimage1 = int(preimage1, 2)
preimage1 = format(preimage1, '032x')
print('preimage1: ', preimage1)
h_preimage1 = sha3_224_hex(preimage1)

print('PW1: ', h_preimage1)
print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
hashM1 = sha3_224_hex_formatter(m1)
print('hashM1: ', hashM1)

nonce2 = 2247850581
nonce2 = bin(nonce2)[2:]
nonce2 = zero_padder(nonce2, 128)

preimage2 = hashM1 + m2 + nonce2
print('Length of PreImage2: ', len(preimage2))

preimage2 = int(preimage2, 2)
preimage2 = format(preimage2, '032x')
print('preimage2: ', preimage2)

h_preimage2 = sha3_224_hex(preimage2)
print('PW2: ', h_preimage2)

# (c) PreImageOfPW1=h(amt0)||m1||nonce1, PreImageOfPW1=h(m1)||m2||nonce2, those two variables should be hex strings with on prefix of 0x
# PreImageOfPW1=""
# PreImageOfPW2=""

#--------------------------------------------------------------------------------

#Part 3: DSA signature and verification
# DSA signature function, p, q, g, k, sk are integers, Message are hex strings of even length.
def Sign( p, q, g, k, sk, Message ):
	r = pow(g, k1, p) % q
	hOfM = sha3_224_hex_formatter(Message)
	hOfM_int = int(hOfM, 2)
	knegativeOne = pow(k, -1, q)
	s = (knegativeOne*(hOfM_int + (sk*r))) % q
	return r,s

# # DSA verification function,  p, q, g, k, pk are integers, Message are hex strings of even length.
def Verify( p, q, g, pk, Message, r, s ):
	hOfM = sha3_224_hex_formatter(Message)
	hOfM_int = int(hOfM, 2)
	sNegativeOne = pow(s, -1, q)
	w = sNegativeOne % q
	u1 = (hOfM_int*w) % q
	u2 = (hOfM_int*r) % q
	v = ((pow(g, u1)*pow(pk, u2)) % p) % q
	if v == r:
		return True
	else:   
		return False