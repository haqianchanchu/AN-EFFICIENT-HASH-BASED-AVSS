from pypairing import ZR as blsZR, G1 as blsG1
from pypairing import Curve25519ZR as ZR
from GoSSamer.crypto.field import GF, GFElement
from GoSSamer.crypto.polynomial import polynomials_over

class Serial:
    def __init__(self, field):
        self.field = field

    def serialize_fs_GFElement(self, f_list):
        data = [f.to_bytes() for f in f_list]
        data_bytes = b''.join(data)
        return data_bytes

    def deserialize_fs_GFElement(self, data_bytes):
        polynomial = polynomials_over(self.field)
        poly = polynomial.random(2)
        element_size = len(poly(0).to_bytes()) 
        assert len(data_bytes) % element_size == 0, "data_bytes length is not a multiple of element size"

        num_elements = len(data_bytes) // element_size
        elements = [
            GFElement.from_bytes(data_bytes[i * element_size : (i + 1) * element_size], self.field)
            for i in range(num_elements)
        ]
        return elements
    
    def serialize_polynomial_bi(self, poly_bi):
        """
        Serialize a Polynomial_bi object to bytes.

        Args:
            poly_bi (Polynomial_bi): The bivariate polynomial to serialize.

        Returns:
            bytes: Serialized byte representation.
        """
        deg_x = len(poly_bi.coeffs)
        deg_y = max((len(row) for row in poly_bi.coeffs), default=0)
        #num_bytes = (self.field.modulus.bit_length() + 7) // 8

        data = deg_x.to_bytes(2, "big") + deg_y.to_bytes(2, "big")

        for i in range(deg_x):
            row = poly_bi.coeffs[i]
            for j in range(deg_y):
                c = row[j] if j < len(row) else self.field(0)
                data += c.to_bytes()
        return data
    
    def deserialize_polynomial_bi(self, b, poly_bi_class):
        """
        Deserialize bytes back into a Polynomial_bi object.

        Args:
            b (bytes): The serialized bytes.
            poly_bi_class: A class returned by polynomials_over_bi(field)

        Returns:
            Polynomial_bi: Reconstructed polynomial.
        """
        deg_x = int.from_bytes(b[:2], "big")
        deg_y = int.from_bytes(b[2:4], "big")
        #num_bytes = (self.field.modulus.bit_length() + 7) // 8
        num_bytes = (255 + 7) // 8

        coeffs = []
        offset = 4
        for i in range(deg_x):
            row = []
            for j in range(deg_y):
                chunk = b[offset:offset + num_bytes]
                value = int.from_bytes(chunk, "big") % self.field.modulus
                row.append(self.field(value))
                offset += num_bytes
            coeffs.append(row)

        return poly_bi_class(coeffs)
    
    def serialize_polynomial(self, poly):
        """
        Serialize a univariate polynomial (Polynomial) to bytes.

        Args:
            poly (Polynomial): The polynomial to serialize.

        Returns:
            bytes: Serialized byte representation.
        """
        coeffs = poly.coeffs
        deg = len(coeffs)
        num_bytes = (self.field.modulus.bit_length() + 7) // 8

        # First 2 bytes for degree
        data = deg.to_bytes(2, "big")
        for c in coeffs:
            data += c.to_bytes()
        return data

    def deserialize_polynomial(self, b, poly_class):
        """
        Deserialize bytes into a Polynomial object.

        Args:
            b (bytes): Serialized bytes.
            poly_class: A class returned by polynomials_over(field)

        Returns:
            Polynomial: Reconstructed polynomial.
        """
        deg = int.from_bytes(b[:2], "big")
        num_bytes = (self.field.modulus.bit_length() + 7) // 8
        coeffs = []

        offset = 2
        for _ in range(deg):
            chunk = b[offset:offset + num_bytes]
            value = int.from_bytes(chunk, "big") % self.field.modulus
            coeffs.append(self.field(value))
            offset += num_bytes

        return poly_class(coeffs)
    
    def serialize_int_set(self, s: set) -> bytes:
        """
        Serialize a set of integers to bytes.
        First 2 bytes store the set size, each int is stored in 4 bytes (big-endian).
        """
        assert all(isinstance(x, int) for x in s), "All elements must be integers"
        data = len(s).to_bytes(2, 'big')
        for x in sorted(s):  # Sorting is optional, useful for deterministic encoding
            data += x.to_bytes(4, 'big')  # 4 bytes per int (supports up to 2^32-1)
        return data

    def deserialize_int_set(self, b: bytes) -> set:
        """
        Deserialize bytes into a set of integers.
        Assumes 2-byte size header and 4-byte integers.
        """
        count = int.from_bytes(b[:2], 'big')
        s = set()
        offset = 2
        for _ in range(count):
            val = int.from_bytes(b[offset:offset+4], 'big')
            s.add(val)
            offset += 4
        return s
    def serialize_fs(self, f_list):    
        n = len(f_list)
        data = bytearray()
        for i in range(n):
            f = f_list[i]
            data.extend(f.__getstate__())
        return data
    
    def deserialize_fs(self, data):    
        n = len(data)//self.f_size
        fs = [None for _ in range(n)]
        for i in range(n):            
            f = self.ZR()
            f.__setstate__(data[i*self.f_size:(i+1)*self.f_size])
            fs[i] = f
        return fs



