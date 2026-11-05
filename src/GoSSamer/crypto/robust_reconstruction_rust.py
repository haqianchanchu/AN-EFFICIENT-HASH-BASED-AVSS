from GoSSamer.crypto.polynomial import polynomials_over
from GoSSamer.crypto.reed_solomon_rust import (
    Algorithm,
    EncoderFactory,
    DecoderFactory,
    RobustDecoderFactory,
)
from GoSSamer.crypto.reed_solomon_rust import IncrementalDecoder

# TODO: Abstract this to a separate file instead of importing it from here.
from GoSSamer.crypto.batch_reconstruction import fetch_one

import logging
logger = logging.getLogger(__name__)



async def robust_reconstruct(field_futures, field, n, t, point, degree, batch_size):
    # logger.debug(f'field_futures = {field_futures}, field = {field}, n = {n}, t = {t}, point = {point}, degree = {degree}, batch_size = {batch_size}')
    use_omega_powers = point.use_omega_powers
    enc = EncoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    # print(2)
    dec = DecoderFactory.get(
        point, Algorithm.FFT if use_omega_powers else Algorithm.VANDERMONDE
    )
    # print(3)
    robust_dec = RobustDecoderFactory.get(t, point, algorithm=Algorithm.GAO)
    # print(4)
    incremental_decoder = IncrementalDecoder(enc, dec, robust_dec, degree, batch_size, t)
    # print(5)

    async for (idx, d) in fetch_one(field_futures):
        # print(f'robustrec', d[0], d[1])
        incremental_decoder.add(d[0], d[1])
        if incremental_decoder.done():
            polys, errors = incremental_decoder.get_results()
            # logger.debug(f'polys = {polys}, errors = {errors}')
            return [polynomials_over(field)(poly) for poly in polys], errors
    return None, None
