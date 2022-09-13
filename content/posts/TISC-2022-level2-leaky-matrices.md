---
title: "TISC 2022 Level 2 - Leaky Matrices"
destription: "A cryptography challenge during TISC 2022"
date: 2022-09-12T00:02:00+08:00
draft: true
tags:
    - ctf
    - tisc-2022
    - cryptography
    - python
    - linear-algebra
categories:
    - ctf
    - writeup
    - tisc-2022
---

## Leaky Matrices Challenge Description

```
DESCRIPTION
Topic: Cryptography

Looks like PALINDROME implemented their own authentication protocol and cryptosystem to provide a secure handshake between any 2 services or devices. It does not look secure to us, can you take a look at what we have got?

Try to fool their authentication service: nc chal00bq3ouweqtzva9xcobep6spl5m75fucey.ctf.sg 56765

ATTACHED FILES
2WKV_Whitepaper.pdf
```

## Introduction
We're given a [PDF file](https://github.com/quentinkhoo/quentinkhoo.github.io/blob/main/static/files/posts/tisc2022/2WKV_Whitepaper.pdf) that describes an (in)secure Authentication Scheme and our goal is to break the authentication scheme. In the PDF file, we can find the source code for running the authentication scheme described:

```python
import sys
import numpy as np

banner = """
Hello!!!
"""

def sysout(fstr):
	sys.stdout.write(fstr)
	sys.stdout.flush()

def prompt(fstr):
	guards = "=" * len(fstr)
	sysout(f"{guards}\n{fstr}\n{guards}\n")

def vectostr(v):
	return "".join(map(str, v.reshape(-1)))

def strtovec(s, rows=8, cols=1):
	return np.fromiter(list(s), dtype="int").reshape(rows, cols)

def win():
	prompt(f"Here is your flag: penis")

if __name__ == "__main__":
	sysout(banner)

	prompt("Challenge Me!")
	for i in range(8):
		input_vec = input(f"Challenge Me #{i+1:02} < -- ")
		assert len(input_vec) == 8
		assert input_vec.count("1") + input_vec.count("0") == 8
		input_vec = strtovec(input_vec)
		output_vec = (SECRET_KEY @ input_vec) & 1
		sysout(f"My Response --> {vectostr(output_vec)}\n")

	prompt("Challenge You!")
	for i in range(8):
		input_vec = np.round(np.random.rand(8,1)).astype("int")
		sysout(f"Challenge You #{i+1:02} --> {vectorstr(input_vec)}\n")
		test_vec = input(f"Your Response <-- ")
		assert len(test_vec) == 8
		assert test_vec.count("1") + test_vec.count("0") == 8
		test_vec = strtovec(test_vec)
		answer_vec = (SECRET_KEY @ input_vec) & 1
		assert (answer_vec == test_vec).all()

	prompt("All challenges passed :)")
	win()
```

(Okay I did not bother typing out the banner...)

## The Solution
In short, the challenge can be rephrased into a linear algebra question as such:

"Given a hidden 8\*8 matrix M1 and an oracle that allows inputting an 8\*8 matrix M2, returning the result `(M1 * M2) AND 1`, retrieve the hidden 8\*8 matrix M".

If you're familiar with linear algebra, you might be familiar with the concept of the [identity matrix](https://en.wikipedia.org/wiki/Identity_matrix), which has a property that if you use take any n*n matrix M and multiply it with the identity Matrix of the same n\*n size I, you would get back M. And this is the exact property we would be looking to exploit in this challenge!

