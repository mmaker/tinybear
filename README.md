# Tinybear (• ֎ •)

**WARNING: Proceed with caution! This code's not constant time and is probably broken in a dozen different ways. It has not been audited publicly, and the API will experience modifications.**

This is a gadget proof system for proving that

$$\text{ctx} = \text{AES}(k, m).$$

where $m$, the message, is committed as a Pedersen commitment $M$
and  $k$, the key, is committed with the other round keys into a Pedersen commitment $K$.

Internally, the protocol uses 1 single invocation of a lookup protocol.
More precisely, the AES circuit is translated into a lookup of:

- AES-128: 1808 elements in a table of 768 elements.
- AES-256: 2576 elements in a table of 768 elements.

we use log-derivates techniques from [[Hab22]](https://eprint.iacr.org/2022/1530),
good old sumcheck,
and and 𝛴-protocols to prove the polynomial relation.

## Proof size

Proof size: 80KB (>78.98KB are the 𝛴-protocols 💀).

## Performances

Proving time for a Mac M1 Pro.

```text
aes128/prove            time:   [28.198 ms 28.403 ms 28.644 ms]
aes256/prove            time:   [33.040 ms 33.505 ms 34.060 ms]
aes128/verify           time:   [12.334 ms 12.606 ms 12.937 ms]
aes256/verify           time:   [12.966 ms 13.034 ms 13.112 ms]
```

without multithreading:

```text
aes128/prove            time:   [65.047 ms 65.178 ms 65.318 ms]
aes256/prove            time:   [69.770 ms 69.851 ms 69.938 ms]
aes128/verify           time:   [36.984 ms 37.030 ms 37.083 ms]
aes256/verify           time:   [44.802 ms 44.920 ms 45.060 ms]
```

on battery and without multithreading:

```text
aes128/prove            time:   [84.010 ms 84.062 ms 84.118 ms]
aes256/prove            time:   [91.787 ms 91.909 ms 92.042 ms]
aes128/verify           time:   [48.744 ms 48.788 ms 48.834 ms]
aes256/verify           time:   [58.989 ms 59.089 ms 59.203 ms]
```

## High-level overview

AES can be implemented using only 3 operations:

- 4-bit XOR, a map $(\mathbb{F}_2^4)^2 \to (\mathbb{F}_2^4)$
- SBOX, a map $\mathbb{F}_2^8 \to \mathbb{F}_2^8$
- RJ2 (multiplication by Rijndael(2)), a map $\mathbb{F}_2^8 \to \mathbb{F}_2^8$.

The prover commits to inputs $\textsf{in}$ and outputs $\textsf{out}$ for each function (the initial input, the keys, and the final output are part of the statement).
The verifier sends a challege $c$.
The prover shows that $\textsf{in} + c \cdot \textsf{out}$ is contained in the table of all possible evaluations (in this case, made of $256\cdot 3 = 768$ elements).
This is a lookup protocol.

The lookup protocol allows us to check that a vector $\vec f$ committed by the prover
has all its elements contained in a vector $\vec t$ (known by the verifier)
if there exists $\vec m$ such that the rational polynomial equation below is satisfied:

$$
\sum_i \frac{m_i}{x + t_i} = \sum_i \frac{1}{x + f_i}
$$

(Informally, $\vec m$ is the number of times each $t_i$ appears in $\vec f$.)
The above equation can be tested as follows:

- the prover send a commitment to $\vec m$,
- the verifier send a challenge $c_l$ and computes $\vec h = [\frac{1}{c_l + t_i}]_i$
- the prover sends a commitment to $\vec g = [\frac{1}{c_l + f_i}]_i$

Then running an inner-product to prove that:

- $\langle \vec m, \vec h\rangle = \langle \vec g, \vec 1\rangle$
- $\vec g \circ (\vec f + c_l) = \vec 1$

We implement the inner-product using sumcheck and Schnorr proofs (oh yes).

## Improvements

A lot of techniques will improve the asymptotic and concrete efficiency of the protocol.

1. Fixed-base multiplication
2. log-sized protocols (à-la-bulletproofs) for reducing the proof size.
3. Lowering the sumcheck challenges to 16 bytes. This should maintain soundness guarantees in the generic group model.
