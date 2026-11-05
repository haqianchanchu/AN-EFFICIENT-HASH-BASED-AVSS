# coding=utf-8
from collections import defaultdict
import zfec
import logging
import hashlib
import math


logger = logging.getLogger(__name__)
logger.setLevel(logging.ERROR)
# Uncomment this when you want logs from this file.
# logger.setLevel(logging.NOTSET)


#####################
#    zfec encode    #
#####################
def encode(k, n, m):
    """Erasure encodes string ``m`` into ``n`` blocks, such that any ``k``
    can reconstruct.
    :param int k: k
    :param int n: number of blocks to encode string ``m`` into.
    :param bytes m: bytestring to encode.
    :return list: Erasure codes resulting from encoding ``m`` into
        ``n`` blocks using ``zfec`` lib.
    """
    try:
        m = m.encode()
    except AttributeError:
        pass
    encoder = zfec.Encoder(k, n)
    assert k <= 256  # TODO: Record this assumption!
    # pad m to a multiple of K bytes
    padlen = k - (len(m) % k)
    m += padlen * chr(k - padlen).encode()
    step = len(m) // k
    blocks = [m[i * step : (i + 1) * step] for i in range(k)]
    stripes = encoder.encode(blocks)
    return stripes


def decode(k, n, stripes):
    """Decodes an erasure-encoded string from a subset of stripes
    :param list stripes: a container of :math:`n` elements,
        each of which is either a string or ``None``
        at least :math:`k` elements are strings
        all string elements are the same length
    """
    assert len(stripes) == n
    blocks = []
    blocknums = []
    for i, block in enumerate(stripes):
        if block is None:
            continue
        blocks.append(block)
        blocknums.append(i)
        if len(blocks) == k:
            break
    else:
        raise ValueError("Too few to recover")
    decoder = zfec.Decoder(k, n)
    rec = decoder.decode(blocks, blocknums)
    m = b"".join(rec)
    padlen = k - m[-1]
    m = m[:-padlen]
    return m


#####################
#    Merkle tree    #
#####################
def hash(x):
    assert isinstance(x, (str, bytes))
    try:
        x = x.encode()
    except AttributeError:
        pass
    return hashlib.sha256(x).digest()

import hashlib

def hash_to_field(x, field):
    """
    WARNING: This is an insecure academic/test version of hash-to-field.
    Do NOT use in production cryptographic protocols.

    This function maps an input string or bytes to a field element in GF(p),
    by computing SHA-256(x), converting the digest to an integer, and reducing mod p.

    Args:
        x (str or bytes): Input to be hashed.
        field (GF): A field instance (e.g., GF(p)).

    Returns:
        GFElement: A pseudorandom-looking field element in GF(p).
    """
    assert isinstance(x, (str, bytes)), "Input must be a string or bytes"
    if isinstance(x, str):
        x = x.encode()

    digest = hashlib.sha256(x).digest()  # Insecure hash for field mapping
    value = int.from_bytes(digest, "big")
    
    return field(value)  # Weak uniformity; use only for simulation/research


def ceil(x):
    return int(math.ceil(x))


def merkle_tree(str_list):
    """Builds a merkle tree from a list of :math:`n` strings (:math:`n`
    at least 1)
    :return list: Merkle tree, a list of ``2*ceil(n)`` strings. The root
         digest is at ``tree[1]``, ``tree[0]`` is blank.
    """
    n = len(str_list)
    assert n >= 1
    bottomrow = 2 ** ceil(math.log(n, 2))
    mt = [b""] * (2 * bottomrow)
    for i in range(n):
        mt[bottomrow + i] = hash(str_list[i])
    for i in range(bottomrow - 1, 0, -1):
        mt[i] = hash(mt[i * 2] + mt[i * 2 + 1])
    return mt


def get_merkle_branch(index, mt):
    """Computes a merkle tree from a list of leaves.
    """
    res = []
    t = index + (len(mt) >> 1)
    while t > 1:
        res.append(mt[t ^ 1])  # we are picking up the sibling
        t //= 2
    return res


def merkle_verify(n, val, root_hash, branch, index):
    """Verify a merkle tree branch proof
    """
    assert 0 <= index < n
    # XXX Python 3 related issue, for now let's tolerate both bytes and
    # strings
    assert isinstance(val, (str, bytes))
    assert len(branch) == ceil(math.log(n, 2))
    # Index has information on whether we are facing a left sibling or a right sibling
    tmp = hash(val)
    tindex = index
    for br in branch:
        tmp = hash((tindex & 1) and br + tmp or tmp + br)
        tindex >>= 1
    if tmp != root_hash:
        logger.info(
            f"Verification failed with {hash(val)} {root_hash} \
        {branch} {tmp == root_hash}"
        )
        return False
    return True