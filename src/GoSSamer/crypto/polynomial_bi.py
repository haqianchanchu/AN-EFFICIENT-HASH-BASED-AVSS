import logging
import operator
from functools import reduce
from itertools import zip_longest

from adkg.ntl import fft as fft_cpp
from adkg.ntl import fft_interpolate as fft_interpolate_cpp

from GoSSamer.crypto.polynomial import polynomials_over

from .elliptic_curve import Subgroup
from .field import GF

import logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

def strip_trailing_zeros_bi(coeffs):
    """
    Removes trailing zeros from a 2D coefficient matrix of a bivariate polynomial.
    Specifically:
      - Trims trailing zeros from each row (corresponding to y-degree terms).
      - Removes entire zero rows at the bottom (corresponding to x-degree terms).
    
    Args:
        coeffs (List[List[field]]): 2D list where coeffs[i][j] represents the coefficient for x^i * y^j.

    Returns:
        List[List[field]]: A cleaned coefficient matrix with trailing zeros removed.
    """
    if not coeffs:
        return []

    # Step 1: Trim trailing zeros from each row (y-axis cleanup)
    cleaned_rows = []
    for row in coeffs:
        if not row:
            cleaned_rows.append([])
            continue
        for j in range(len(row) - 1, -1, -1):
            if row[j] != 0:
                break
        cleaned_rows.append(row[:j + 1])

    # Step 2: Trim entire trailing rows that are all zero (x-axis cleanup)
    for i in range(len(cleaned_rows) - 1, -1, -1):
        if all(c == 0 for c in cleaned_rows[i]):
            continue
        else:
            break
    return cleaned_rows[:i + 1]


_poly_cache = {}

def polynomials_over_bi(field):
    # assert type(field) is GF or field == ZR or field == bpZR
    # field_type = GFElement if type(field) is GF else field
    field_type = type(field(0))
    if field in _poly_cache:
        return _poly_cache[field]
    
    class Polynomial_bi(object):
        def __init__(self, coeffs):
            """
            Initialize a bivariate polynomial with a 2D coefficient matrix.
            Each coeffs[i][j] represents the coefficient for x^i * y^j.

            This constructor performs the following:
            1. Removes trailing zero rows and columns using `strip_trailing_zeros_2d`.
            2. Converts integer coefficients to field elements.
            3. Validates that all coefficients match the expected field type.
            """
            # Step 1: Clean the input to remove redundant zeros
            self.coeffs = strip_trailing_zeros_bi(coeffs)

            # Step 2: Convert integers to field elements and ensure correct type
            for i in range(len(self.coeffs)):
                row = self.coeffs[i]
                for j in range(len(row)):
                    if isinstance(row[j], int):
                        self.coeffs[i][j] = field(row[j])
                    assert isinstance(self.coeffs[i][j], field_type), (
                        f"Invalid coefficient at position ({i},{j}): "
                        f"type={type(self.coeffs[i][j])}, expected={field_type}"
                    )

            # Step 3: Store the field reference for later arithmetic
            self.field = field
        
        # def __call__(self, x, y):
        #     """
        #     Evaluate the bivariate polynomial at a given point (x, y).

        #     Args:
        #         x (field element): The x-coordinate.
        #         y (field element): The y-coordinate.

        #     Returns:
        #         field element: The value of the polynomial f(x, y).
        #     """
        #     result = self.field(0)
        #     for i, row in enumerate(self.coeffs):
        #         for j, coef in enumerate(row):
        #             result += coef * (x ** i) * (y ** j)
        #     return result
        
        def __call__(self, x, y, x_pows=None, y_pows=None):
            # 如果传入幂缓存，用它；否则自己计算
            if x_pows is None:
                x_pows = [x**a for a in range(len(self.coeffs))]
            if y_pows is None:
                y_pows = [y**b for b in range(len(self.coeffs[0]))]

            result = self.field(0)
            for i, row in enumerate(self.coeffs):
                for j, coef in enumerate(row):
                    result += coef * x_pows[i] * y_pows[j]
            return result
    
        @classmethod
        def random_bi(cls, degree_x, degree_y, x_poly_0=None, y_poly_0=None):
            """
            Generate a random bivariate polynomial of degree (degree_x, degree_y).

            Optionally fix the values along y=0 using a univariate polynomial x_poly_0,
            or along x=0 using y_poly_0.

            Args:
                degree_x (int): Maximum degree in x.
                degree_y (int): Maximum degree in y.
                x_poly_0 (Polynomial): A univariate polynomial specifying f(x, 0).
                y_poly_0 (Polynomial): A univariate polynomial specifying f(0, y).

            Returns:
                Polynomial_bi: A random bivariate polynomial with optional fixed line.
            """
            # Step 1: Generate a full coefficient matrix with random values
            coeffs = [
                [field.random() for _ in range(degree_y + 1)]
                for _ in range(degree_x + 1)
            ]

            # Step 2a: If x_poly_0 is provided, set f(x, 0)
            if x_poly_0 is not None:
                assert hasattr(x_poly_0, 'coeffs'), "x_poly_0 must be a univariate polynomial with 'coeffs'"
                assert x_poly_0.degree() <= degree_x, (
                    f"x_poly_0 degree ({x_poly_0.degree()}) exceeds degree_x ({degree_x})"
                )
                for i in range(degree_x + 1):
                    coeffs[i][0] = x_poly_0.coeffs[i] if i < len(x_poly_0.coeffs) else field(0)

            # Step 2b: If y_poly_0 is provided, set f(0, y)
            if y_poly_0 is not None:
                assert hasattr(y_poly_0, 'coeffs'), "y_poly_0 must be a univariate polynomial with 'coeffs'"
                assert y_poly_0.degree() <= degree_y, (
                    f"y_poly_0 degree ({y_poly_0.degree()}) exceeds degree_y ({degree_y})"
                )
                for j in range(degree_y + 1):
                    coeffs[0][j] = y_poly_0.coeffs[j] if j < len(y_poly_0.coeffs) else field(0)

            # Step 3: Return the polynomial object
            return cls(coeffs)
        

        def evaluate_fft(self, omega_x, omega_y, n):
            """
            Perform Fast Fourier Transform (FFT) to evaluate a bivariate polynomial at given points.

            Args:
                omega_x (field_type): The root of unity for the x variable.
                omega_y (field_type): The root of unity for the y variable.
                n (int): The number of evaluation points, must be a power of two.

            Returns:
                list: A 2D list representing the evaluated values of the bivariate polynomial at all points.
            """
            # Ensure that n is a power of two
            assert n & (n - 1) == 0, "n must be power of two"

            # Ensure omega_x and omega_y are field elements
            assert type(omega_x) is field_type and type(omega_y) is field_type, "omega_x and omega_y must be field elements"

            # Ensure omega_x and omega_y are n-th roots of unity
            assert omega_x ** n == 1, "omega_x must be an n'th root of unity"
            assert omega_y ** n == 1, "omega_y must be an n'th root of unity"

            # Ensure omega_x and omega_y are primitive n-th roots of unity
            assert omega_x ** (n // 2) != 1, "omega_x must be a primitive n'th root of unity"
            assert omega_y ** (n // 2) != 1, "omega_y must be a primitive n'th root of unity"

            # Perform FFT on the x direction (coefficients of the polynomial)
            fft_x = fft(self, omega_x, n)

            # Perform FFT on the y direction (coefficients of the polynomial)
            fft_y = fft(self, omega_y, n)

            # Initialize a 2D result matrix for storing the evaluated values
            result = [[0 for _ in range(n)] for _ in range(n)]

            # Multiply the results of FFT in both x and y directions
            for i in range(n):
                for j in range(n):
                    result[i][j] = fft_x[i] * fft_y[j]  # Combine FFT results from both directions

            # Return the result matrix, which contains the polynomial evaluations at all points
            return result
        
        def get_poly_x(self, y_index):
            """
            Fix y = y_index, and return the univariate polynomial f(x, y_index) as a list of coefficients in x.

            This computes:
                f(x, y_index) = sum_i (sum_j a_{i,j} * y_index^j) * x^i

            Returns:
                List[field]: Coefficients of univariate polynomial in x
            """
            y = self.field(y_index)
            result_coeffs = []

            for row in self.coeffs:
                acc = self.field(0)
                y_pow = self.field(1)
                for coef in row:
                    acc += coef * y_pow
                    y_pow *= y
                result_coeffs.append(acc)

            poly = polynomials_over(self.field)
            return poly(result_coeffs)



        def get_poly_y(self, x_index):
            """
            Fix x = x_index and return the univariate polynomial f(x_index, y) as a univariate Polynomial object in y.

            Returns:
                Polynomial: f(x_index, y) = sum_j c_j * y^j
            """
            x = self.field(x_index)

            # 获取最大 y 次数
            max_deg_y = max((len(row) for row in self.coeffs), default=0)

            result_coeffs = [self.field(0) for _ in range(max_deg_y)]

            for i, row in enumerate(self.coeffs):
                x_pow = x ** i
                for j, coeff in enumerate(row):
                    result_coeffs[j] += coeff * x_pow

            from .polynomial import polynomials_over
            Poly = polynomials_over(self.field)
            return Poly(result_coeffs)




        _lagrange_cache = {}

        @classmethod
        def clear_cache(cls):
            cls._lagrange_cache.clear()

        def __add__(self, other):
            assert isinstance(other, Polynomial_bi), "Can only add another Polynomial_bi"

            max_x = max(len(self.coeffs), len(other.coeffs))
            max_y = max(
                max((len(row) for row in self.coeffs), default=0),
                max((len(row) for row in other.coeffs), default=0)
            )

            result = [
                [self.field(0) for _ in range(max_y)]
                for _ in range(max_x)
            ]

            for i, row in enumerate(self.coeffs):
                for j, val in enumerate(row):
                    result[i][j] += val

            for i, row in enumerate(other.coeffs):
                for j, val in enumerate(row):
                    result[i][j] += val

            return Polynomial_bi(result)
        
        def __rmul__(self, scalar):
            """
            Scalar multiplication for bivariate polynomial: scalar * poly.

            Args:
                scalar (int or field element): A scalar to multiply with all coefficients.

            Returns:
                Polynomial_bi: A new polynomial where each coefficient is multiplied by scalar.
            """
            if isinstance(scalar, int):
                scalar = self.field(scalar)
            assert isinstance(scalar, type(self.field(0))), "Scalar must be a field element"

            result_coeffs = []
            for row in self.coeffs:
                result_row = [scalar * c for c in row]
                result_coeffs.append(result_row)

            return Polynomial_bi(result_coeffs)

        __mul__ = __rmul__

    def zero():
        return Polynomial_bi([])

    _poly_cache[field] = Polynomial_bi
    return Polynomial_bi

def fft_helper(a, omega, field):
    """
    Given coefficients A of polynomial this method does FFT and returns
    the evaluation of the polynomial at [omega^0, omega^(n-1)]

    If the polynomial is a0*x^0 + a1*x^1 + ... + an*x^n then the coefficients
    list is of the form [a0, a1, ... , an].
    """
    n = len(a)
    assert not (n & (n - 1)), "n must be a power of 2"

    if n == 1:
        return a

    b, c = a[0::2], a[1::2]
    b_bar = fft_helper(b, pow(omega, 2), field)
    c_bar = fft_helper(c, pow(omega, 2), field)
    a_bar = [field(1)] * (n)
    for j in range(n):
        k = j % (n // 2)
        a_bar[j] = b_bar[k] + pow(omega, j) * c_bar[k]
    return a_bar


def fft(poly, omega, n):
    assert n & n - 1 == 0, "n must be a power of 2"
    assert len(poly.coeffs) <= n
    assert pow(omega, n) == 1
    assert pow(omega, n // 2) != 1

    padded_coeffs = poly.coeffs + ([poly.field(0)] * (n - len(poly.coeffs)))
    return fft_helper(padded_coeffs, omega, poly.field)
