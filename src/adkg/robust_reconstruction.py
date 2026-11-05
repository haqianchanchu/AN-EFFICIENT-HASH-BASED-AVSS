from adkg.polynomial import polynomials_over
from adkg.reed_solomon import (
    Algorithm,
    EncoderFactory,
    DecoderFactory,
    RobustDecoderFactory,
)
from adkg.reed_solomon import IncrementalDecoder

# TODO: Abstract this to a separate file instead of importing it from here.
from adkg.batch_reconstruction import fetch_one


async def robust_reconstruct(field_futures, field, n, t, point, degree):
    print(1)
    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    print(2)
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    print(3)
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.WELCH_BERLEKAMP)
    print(4)
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, 1, t)
    print(5)

    async for (idx, d) in fetch_one(field_futures):
        print(idx, d)
        incremental_decoder.add(idx, [d.value])
        print(7)
        if incremental_decoder.done():
            print(8)
            polys, errors = incremental_decoder.get_results()
            print(9)
            return polynomials_over(field)(polys[0]), errors
    return None, None
