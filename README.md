# Coooppersmith

## Challenge Description

This challenge works as following:
  1. It asks prefix input, in hex, with length no more than 120.
  2. It generates a 128-hex (128 * 4 = 512 bit) prime `s`.
  3. It generates two primes `p` and `q` based on `s` using (Pocklington's Theorem)[https://www.tandfonline.com/doi/abs/10.1080/00207160212708]
  4. It sends the public key to the player, so player knows `n` and `e`.
  5. It sends the encrypted question (what's the sum of random a + random b?), and asks for solution.
  6. After checking the solution, it sends the encrypted flag msg.

## Solution

  The key is to factorize `n` given the customized prefix of `s`. To solve this, the player can set a prefix, and create a dictionary of primes with the prefix. Next, the player needs to enumerate the primes and solve p using the coopersmith approach. Specifically, find `x` such as:

  $p = 2 * s * x + 1$

  $f = 2 * s * x + 1 = 0 mod n$

The original coopersmith requires the equation to be monic, i.e., the coefficient of `x` is 1. So we convert it to:

  $f = x + (2 * s)^-1 mod n$

Now we get it. The key function (cooppersmith) is shown below.

```python
def find_dd(n, s):
    # find prime s with the prefix of [prefix] and in hex length of [prime_len]
    s_inverse = inverse_mod(2 * s, n)
    PR = PolynomialRing(Zmod(n), names=('x',))
    (x,) = PR._first_ngens(1)
    # f = 2 * s * x + 1 -> f = x + (2 * s)^-1 mod n
    f = x + s_inverse
    # print f
    f.small_roots()
    try:
        # find root < 2^k bits with factor >= n^0.4
        xs = f.small_roots(X=s, beta=0.4)
        # X can't be too large like 2 * (s + 1). I don't know why but whatever
        p = xs[0] * 2 * s + 1
        print p
        d = calculate_d(n, long(p))
        return d
    except Exception:
        return None
```
