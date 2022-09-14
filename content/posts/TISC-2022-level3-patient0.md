---
title: "TISC 2022 Level 3 - PATIENT0"
destription: "A forensics challenge during TISC 2022"
date: 2022-09-12T00:03:00+08:00
draft: false
tags:
    - ctf
    - tisc-2022
    - forensics
    - crc32
    - bruteforce
    - autopsy
    - hash-collision
    - ntfs
    - bios-parameter-block
    - ads
    - truecrypt
categories:
    - ctf
    - writeup
    - tisc-2022
---

## Patient0 Challenge Description
This was a forensics challenge unlocked at level 3 that was part of the recent [TISC 2022](https://www.csit.gov.sg/events/tisc/tisc-2022) CTF organised by [CSIT](https://www.csit.gov.sg/). TISC 2022 was an individual CTF that is level-based and not exactly a typical jeopardy-style CTF, meaning that only 1 challenge is released at a time and only after you solve that 1 challenge do you unlock the next one. In this writeup, I will discuss my approach towards solving this particular forensics challenge.

## Part 1
```
DESCRIPTION
Topic: Forensics

Palindrome has spread some virus to corrupt machines causing incorrect readings in patients' health measurements and rending them unusable. Inspect the file and see if you can uncover the 8 corrupted bytes that renders the file system unusable?

Submit your flag in this format: TISC{last 4 bytes in 8 lowercase hex characters}
```

In the process of solving Part 1, I definitely jumped the gun and enumerated the file much more than necessary to solve the first part. Right off the bat I went straight into analyzing what kind of file it was with our trusty `file` command:

### Enumerating the Provided File
```bash
└─$ file PATIENT0    
PATIENT0: DOS/MBR boot sector, code offset 0x52+2, OEM-ID "NTFS    ", sectors/cluster 8, Media descriptor 0xf8, sectors/track 0, FAT (1Y bit by descriptor); NTFS, physical drive 0xab3566f7, sectors 12287, $MFT start cluster 4, $MFTMirror start cluster 767, bytes/RecordSegment 2^(-1*246), clusters/index block 1, serial number 05c66c6b160cddda1

```

We can see from this that the provided `PATIENT0` file is an NTFS partition.

Let's go ahead and run `fls` on this to see what files are available on it:

```
└─$ fls PATIENT0   
r/r 4-128-1:    $AttrDef
r/r 8-128-2:    $BadClus
r/r 8-128-1:    $BadClus:$Bad
r/r 6-128-1:    $Bitmap
r/r 7-128-1:    $Boot
d/d 11-144-2:   $Extend
r/r 2-128-1:    $LogFile
r/r 0-128-1:    $MFT
r/r 1-128-1:    $MFTMirr
r/r 9-128-2:    $Secure:$SDS
r/r 9-144-7:    $Secure:$SDH
r/r 9-144-4:    $Secure:$SII
r/r 10-128-1:   $UpCase
r/r 10-128-2:   $UpCase:$Info
r/r 3-128-3:    $Volume
r/r 31-128-1:   message.png
r/r 31-128-3:   message.png:$RAND
-/r * 32-128-1: broken.pdf
V/V 256:        $OrphanFiles
```

Hmmm, 3 interesting files found:
- `broken.pdf`
- `message.png`
- `message.png:$RAND` 

### NTFS and Bios Parameter Block
Let's focus on the `broken.pdf` first. Opening up we see the following:

![BPB](/images/posts/tisc-2022-level3-bpb.png)

Hmmm, looks like `BPB` is a clue. After some googling, turns out BPB stands for `BIOS Parameter Block`. The following tables (referenced from [here](http://ntfs.com/ntfs-partition-boot-sector.htm)) describes the data fields and its respective offset:

| Byte Offset | Field Length | Field Name           |
| ----------- | ------------ | -------------------- |
| 0x00        | 3 bytes      | Jump Instruction     |
| 0x03        | LONGLONG     | OEM ID               |
| 0x0B        | 25 bytes     | BPB                  |
| 0x24        | 48 bytes     | Extended BPB         |
| 0x54        | 426 bytes    | Bootstrap Code       |
| 0x01FE      | WORD         | End of Sector Marker |

Ahhh we can see the BPB and Extended BPB starts at `0x0B` and `0x24` respectively, spanning from `0x0B - 0x53`. Let's take a look at this range of bytes and what do they mean:

| Byte Offset | Field Length | Sample Value       | Field Name                                   |
| :---------: | :----------: | ------------------ | -------------------------------------------- |
|    0x0B     |     WORD     | 0x0002             | Bytes Per Sector                             |
|    0x0D     |     BYTE     | 0x08               | Sectors Per Cluster                          |
|    0x0E     |     WORD     | 0x0000             | Reserved Sectors                             |
|    0x10     |   3 BYTES    | 0x000000           | always 0                                     |
|    0x13     |     WORD     | 0x0000             | not used by NTFS                             |
|    0x15     |     BYTE     | 0xF8               | Media Descriptor                             |
|    0x16     |     WORD     | 0x0000             | always 0                                     |
|    0x18     |     WORD     | 0x3F00             | Sectors Per Track                            |
|    0x1A     |     WORD     | 0xFF00             | Number Of Heads                              |
|    0x1C     |    DWORD     | 0x3F000000         | Hidden Sectors                               |
|    0x20     |    DWORD     | 0x00000000         | not used by NTFS                             |
|    0x24     |    DWORD     | 0x80008000         | not used by NTFS                             |
|    0x28     |   LONGLONG   | 0x4AF57F0000000000 | Total Sectors                                |
|    0x30     |   LONGLONG   | 0x0400000000000000 | Logical Cluster Number for the file $MFT     |
|    0x38     |   LONGLONG   | 0x54FF070000000000 | Logical Cluster Number for the file $MFTMirr |
|    0x40     |    DWORD     | 0xF6000000         | Clusters Per File Record Segment             |
|    0x44     |     BYTE     | 0x01               | Clusters Per Index Buffer                    |
|    0x45     |   3 BYTES    | 0x000000           | not used by NTFS                             |
|    0x48     |   LONGLONG   | 0x14A51B74C91B741C | Volume Serial Number                         |
|    0x50     |    DWORD     | 0x00000000         | Checksum                                     |

Hmm, seems like there's an 8 bytes worth of data `not used by NTFS` from `0x20 - 0x27`. Let's investigate this piece of data in a hex editor:

```bash
00000000  EB 52 90 4E  54 46 53 20   20 20 20 00  02 08 00 00                .R.NTFS    .....
00000010  00 00 00 00  00 F8 00 00   00 00 00 00  00 00 00 00                ................
00000020  54 49 53 43  F7 66 35 AB   FF 2F 00 00  00 00 00 00                TISC.f5../......
00000030  04 00 00 00  00 00 00 00   FF 02 00 00  00 00 00 00                ................
```

Hmmmm, we have some `TISC` string, and the challenge description tells us to use the last 4 bytes (`f76635ab`) from the corrupted 8 bytes, giving us the flag `TISC{f76635ab}`.

## Part 2
```
DESCRIPTION
Topic: Forensics

Palindrome must have leaked one of their passwords as the 4 corrupted bytes (Part 1 flag)! Dig deeper to find what was hidden!

Submit your flag in this format: TISC{md5 hash} <-- will be prompted only after opening hidden room.

Note: Please ignore the word 'original' in clue 4.
```

### NTFS Alternate Data Streams (ADS)

Hmm, no additional file(s). Let's go back to looking at our results from our `fls` command, in particular the other 2 files that were seemingly interesting.

```bash
r/r 31-128-1:   message.png
r/r 31-128-3:   message.png:$RAND
```

It seems like we have an [Alternate Data Stream](https://en.wikipedia.org/wiki/NTFS#Alternate_data_stream_(ADS)) hidden within the `message.png` file. An Alternate Data Stream (ADS) is exclusive to an NTFS formatted file system. It is basically another way of hiding a file within a file (although the hidden file is not exactly WITHIN the facade file, it's just forked into another stream, hence the name Alternate Data Stream).

Let's extract both files `message.png` and the ADS to it with `icat`. `icat` allows us to essentially output file contents based on an inode number, which is essentially the second column of data from the `fls` output.

```bash
└─$ icat PATIENT0 31-128-1  >> message.png
└─$ file message.png 
message.png: PNG image data, 1227 x 57, 8-bit/color RGB, non-interlaced
```

Opening up the image we get a base32 encoded text in an image. We can recognise it's base32 from the fact that the letters are all in uppercase.

![message.png](/images/posts/tisc-2022-level3-message.png)

I used an [online tool](https://www.imagetotext.info/) to extract the string out for decoding and with that, I got the next clue!

```bash
└─$ echo "GIXFI2DJOJZXI6JAMZXXEIDUNBSSAZTMMFTT6ICHN4QGM2LOMQQHI2DFEBZXI4TFMFWS4CQ=" | base32 -d               130 ⨯
2.Thirsty for the flag? Go find the stream.
```

Okay, turns out it wasn't so much of a clue for me since I recognised the presence of the ADS already, this clue just confirms it :p

so let's go ahead and extract the ADS and analyze it!

```bash
└─$ icat PATIENT0 31-128-3 >> message.bin  
└─$ file message.bin 
message.bin: data
```

### Encrypted Volumes
Hmmm, a `data` file. Let's open it up in a hex editor and see what's up.

```bash
File: message.bin                ASCII Offset: 0x00000000 / 0x004001F1 (%00)   
00000000  33 2E 41 72  65 20 74 68   65 73 65 20  54 72 75 65                3.Are these True
00000010  20 72 61 6E  64 6F 6D 20   62 79 74 65  73 20 66 6F                 random bytes fo
00000020  72 20 43 72  79 70 74 6F   6C 6F 67 79  3F 4B 76 18                r Cryptology?Kv.
00000030  7A 66 97 EB  45 D8 24 D0   DC 51 7E 42  8D 5A 18 3A                zf..E.$..Q~B.Z.:
```
Hmmm, looks like the header of the file gives us our next clue. We also have the 4th clue at the end of the file.

```bash
00400120  C1 C5 E1 AB  B3 9B 34 00   2E 00 49 00  66 00 20 00                ......4...I.f. .
00400130  79 00 6F 00  75 00 20 00   6E 00 65 00  65 00 64 00                y.o.u. .n.e.e.d.
00400140  20 00 61 00  20 00 70 00   61 00 73 00  73 00 77 00                .a. .p.a.s.s.w.
00400150  6F 00 72 00  64 00 2C 00   20 00 74 00  68 00 65 00                o.r.d.,. .t.h.e.
00400160  20 00 6F 00  72 00 69 00   67 00 69 00  6E 00 61 00                .o.r.i.g.i.n.a.
00400170  6C 00 20 00  72 00 65 00   61 00 64 00  69 00 6E 00                l. .r.e.a.d.i.n.
00400180  67 00 20 00  6F 00 66 00   20 00 74 00  68 00 65 00                g. .o.f. .t.h.e.
00400190  20 00 42 00  50 00 42 00   20 00 77 00  61 00 73 00                .B.P.B. .w.a.s.
004001A0  20 00 61 00  63 00 74 00   75 00 61 00  6C 00 6C 00                .a.c.t.u.a.l.l.
004001B0  79 00 20 00  43 00 68 00   65 00 63 00  6B 00 65 00                y. .C.h.e.c.k.e.
004001C0  64 00 20 00  61 00 6E 00   64 00 20 00  52 00 65 00                d. .a.n.d. .R.e.
004001D0  43 00 68 00  65 00 63 00   6B 00 65 00  64 00 20 00                C.h.e.c.k.e.d. .
004001E0  33 00 32 00  20 00 74 00   69 00 6D 00  65 00 73 00                3.2. .t.i.m.e.s.
004001F0  21 00                                     !. 
```

Alright, let's focus on our 3rd clue first. which states the following:

`3.Are these True random bytes for Cryptology?`

 I initially went down a rabbit hole and thought that the clue meant [Cryptology](https://sourceforge.net/projects/cryptology/) was the encryption software being used.

![facepalm](/images/posts/facepalm.png)

I struggled for awhile to even install it and set it up considering it was an outdated software (which I never did since this only ran on very old versions of Windows), until I saw the clue, which showed the logo of the [TrueCrypt](https://en.wikipedia.org/wiki/TrueCrypt) software.

![truecrypt](/images/posts/tisc-2022-level3-truecrypt.png)

Okay, so we've recognised the encryption software. The 4th clue also tell us the following:

`If you need a password, the original reading of the BPB was also Checked and Checked 32 times.`

This seemed to have hinted towards a key piece of information: `CRC32`

Well, we have `TrueCrypt` and `message.bin`. Using a hexeditor we just needed to remove the header and footer bytes that contains the clue to make the file a legitimate `TrueCrypt` volume for mounting.

I couldn't figure the password until the challenge hint told us that the password was essentially the flag from the Part 1 (AKA `f76635ab`), and so with that let's go ahead and mount the `message.bin` volume on `TrueCrypt`, which shows us an image file `outer.jpg` that shows another hint.

![outer.jpg](/images/posts/tisc-2022-level3-outer.jpg)

### Bruteforcing a CRC32 Hash Collision

A leetspeak text consisting of lowercase alphabets and numbers, with a hangman clue for `hash collision`.

Combining the hints provided and the clues unravelled thus far, it seems like our next step is to bruteforce out a 9 letter password `c-------n` that would have a CRC32 hash collision with the `0xf76635ab`.

I went ahead to to write a script to perform this bruteforce (which I left to run while I was working my full time job):

```python
import string
import itertools
import zlib

clash = 0xf76635ab
print(f"CRC32 to clash: {clash}")

charset = string.digits + string.ascii_lowercase

for i in itertools.permutations(charset, 7):
    tmp = ''.join(i)
    w = 'c' + tmp + 'n'
    c = zlib.crc32(w.encode())
    if c == clash:
        print(f"Word clash found with {w}!!")

```
Turns out that after bruteforcing this the password was revealed to be `c01lis1on` and I totally did not catch the hint that I was supposed to leetspeak the work `collision`. I re-wrote another script just for completeness and more facepalm moments:

```python
import string
import itertools
import zlib

clash = 0xf76635ab
print(f"Aiming to clash with {clash}")

REPLACE = {'a': '4', 'b': '8', 'e': '3', 'g': '6', 'i': '1', 'l': '1', 'o': '0', 's': '5', 't': '7', 'z': '2'}

# Source: https://stackoverflow.com/questions/29151145/how-can-i-get-all-possible-leet-versions-of-a-string-with-optional-substituti
def Leet2Combos(word):
    possibles = []
    for l in word.lower():
        ll = REPLACE.get(l, l)
        possibles.append( (l,) if ll == l else (l, ll) )
    return [ ''.join(t) for t in itertools.product(*possibles) ]


for w in Leet2Combos('collision'):
  c = zlib.crc32(w.encode())
  #print(f"Current word: {w} and CRC32 value: {c}")
  if c == clash:
    print(f"Word clash found with {w}!!")

```

Inputting this new password when mounting the volume gives us a new file `flag.ppsm`! Turns out this was actually a [TrueCrypt Hidden Volume](https://www.truecrypt71a.com/documentation/plausible-deniability/hidden-volume).

Let's see what's this `ppsm` file extension

```bash
└─$ file flag.ppsm   
flag.ppsm: Microsoft PowerPoint 2007+
```

Oh, turns out this is a Microsoft PowerPoint file. Let's go ahead and `unzip` it! We would notice that there's a `media` folder in which we're presented with 3 files:

- `image1.png`
- `image2.jpg`
- `media1.mp3`

Opening up `image2.jpg` we're presented some flipped image.

![image2](/images/posts/tisc-2022-level3-image2.jpg)

Flipping the image we see a string `TISC{md5 hash of sound clip}`.

Ahh I guess sound clip is referring to `media1.mp3`. Let's go get that FLAG

```bash
└─$ md5sum media1.mp3 
f9fc54d767edc937fc24f7827bf91cfe  media1.mp3
```

With that, we have the flag `TISC{f9fc54d767edc937fc24f7827bf91cfe}`

## Final Thoughts
Wow this was an interesting challenge, rather tedious but nonetheless fun! I like how the administrators gave out hints to help the participants interpret the clues much better and make the route of solving much clearer, without which I may have honestly just given up. 

I hope you guys had fun reading this write-up and my struggle(s) as much as I had playing this CTF!

