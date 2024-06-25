from dataclasses import dataclass
from collections import namedtuple
from typing import Self
from crypto import (CryptoSystem, EllipticCurvePublicKey, EllipticCurvePrivateKey, SECP256R1,
                    ec_generate_private_key as gen_priv_key)
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateNumbers, \
    EllipticCurvePublicNumbers
from secrets import randbelow

CURVE_A: int = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
CURVE_B: int = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
CURVE_GEN_POINT: tuple[int, int] = (0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                                    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5)
CURVE_ORDER: int = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551


@dataclass
class EllipticCurve:
    """Representation of an Elliptic Curve: y^2 = x^3 + ax + b"""
    generator_point: "EllipticCurvePoint"
    a: int
    b: int
    n: int = CURVE_ORDER

    def __init__(self, generator_point: tuple[int, int], a: int, b: int, n: int) -> None:
        self.generator_point = EllipticCurvePoint(self, *generator_point)

    def is_on_curve(self, point: "EllipticCurvePoint") -> bool:
        return point.y ** 2 == point.x ** 3 + self.a * point.x + self.b

    def double_point(self, point: "EllipticCurvePoint") -> "EllipticCurvePoint":
        lambda_: float = (3 * point.x ** 2 + self.a) / (2 * point.y)
        return point.add_using_lambda(lambda_, point)

    def multiply_point(self, point: "EllipticCurvePoint", multiplier: int) -> "EllipticCurvePoint":
        multiplier_bits: str = bin(multiplier)[2:]

        transformed_point: EllipticCurvePoint = point

        for i, bit in enumerate(multiplier_bits):
            if i == 0:
                continue

            if bit not in ("1", "0"):
                raise ValueError

            transformed_point = self.double_point(transformed_point)

            if bit == "1":
                transformed_point += point

            transformed_point.x %= self.n
            transformed_point.y %= self.n

    def new_point(self, x: float, y: float) -> "EllipticCurvePoint":
        return EllipticCurvePoint(self, x, y)


@dataclass
class EllipticCurvePoint:
    curve: EllipticCurve
    x: float
    y: float

    def __neg__(self) -> Self:
        return EllipticCurvePoint(self.x, -self.y)

    def __add__(self, other: Self) -> Self:
        if other is self:
            return curve.double_point(self)

        lambda_: float = (other.y - self.y) / (other.x - self.x)
        return self.add_using_lambda(lambda_, other)

    def is_infinity(self) -> bool:
        return self + -self == (0, 0)

    def add_using_lambda(self, lambda_: float, other: Self) -> Self:
        sum_x: float = lambda_ ** 2 - self.x - other.x
        x_val: int = round(sum_x) % self.curve.n
        y_val: int = round(lambda_ * (self.x - sum_x) - self.y) % self.curve.n

        return EllipticCurvePoint(self.curve, x_val, y_val)


@dataclass
class PointAtInfinity(EllipticCurvePoint):
    def __neg__(self) -> Self:
        return self

    def __add__(self, other: Self) -> Self:
        return other

    def is_infinity(self) -> bool:
        return True


NIST_P256: EllipticCurve = EllipticCurve(CURVE_GEN_POINT, CURVE_A, CURVE_B, CURVE_ORDER)


class CustomESCDASystem(CryptoSystem):
    @classmethod
    def generate_keys(cls, key_length: int) -> tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
        curve: EllipticCurve = EllipticCurve()
        priv_key: int = randbelow(CURVE_ORDER)
        pub_key: EllipticCurvePoint = NIST_P256.multiply_point(NIST_P256.generator_point, priv_key)

        pub_nums: EllipticCurvePublicNumbers = EllipticCurvePublicNumbers(round(pub_key.x), round(pub_key.y),
                                                                          SECP256R1())
        priv_nums: EllipticCurvePrivateNumbers = EllipticCurvePrivateNumbers(priv_key, pub_nums)

        return priv_nums.private_key(), pub_nums.public_key()

    def generate_file_signature(self, file_hash: bytes) -> int:
        while True:
            k: int = randbelow(CURVE_ORDER)

            corresponding_point: EllipticCurvePoint = NIST_P256.multiply_point()

    def verify_signature(self, file_hash: bytes, expected_signature: int) -> bool:
        pass


if __name__ == '__main__':
    curve: EllipticCurve = EllipticCurve((
        55066263022277343669578718895168534326250603453777594175500187360389116729240,
        32670510020758816978083085130507043184471273380659243275938904335757337482424),
        a=0, b=7, n=115792089237316195423570985008687907852837564279074904382605163141518161494337
    )
    p1: EllipticCurvePoint = curve.new_point(
        66902724597357857524393598657745691643796678673691961267927766034756458255321,
        41446838359059268811965545805312786852493746987178657624844462697177700943178)

    p2: EllipticCurvePoint = curve.new_point(
        59573147102194928850577496614463885330806641246420659169407163428395054404845,
        96527830740528973512235760395271336484075609618818808805752524123940098791131
    )

    sum_: EllipticCurvePoint = p1 + p2
    print(f"{sum_.x=}\n{sum_.y=}")
