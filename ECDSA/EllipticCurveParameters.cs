using System;
using System.Diagnostics;
using System.Numerics;

namespace ECDSA
{
    public class EllipticCurveParameters
    {
        public BigInteger P;
        public BigInteger A;
        public BigInteger B;

        public EllipticCurveParameters(BigInteger p, BigInteger a, BigInteger b)
        {
            P = p;
            A = a;
            B = b;
        }

        public static bool operator ==(EllipticCurveParameters a, EllipticCurveParameters b)
        {
            return a.P == b.P && a.A == b.A && a.B == b.B;
        }

        public static bool operator !=(EllipticCurveParameters a, EllipticCurveParameters b)
        {
            return !(a == b);
        }

        public bool IsSolution(BigInteger x, BigInteger y)
        {
            var a = BigInteger.ModPow(y, 2, P);
            var b = (x * x * x + A * x + B).Mod(P);
            return a == b;
        }

        public BigInteger EvaluateX(BigInteger x)
        {
            return ((x * x + A) * x + B).Mod(P);
        }

        public BigInteger? GetSlope(BigInteger x, BigInteger y)
        {
            if (!IsSolution(x, y))
                throw new Exception();
            if (y.IsZero)
                return null;
            var dividend = (3 * BigInteger.ModPow(x, 2, P) + A).Mod(P);
            var divisor = (2 * y).ExtendedEuclidean(P);

            var ret = (dividend * divisor).Mod(P);

            Debug.Assert((ret * 2 * y).Mod(P) == dividend);

            return ret;
        }

        protected bool Equals(EllipticCurveParameters other)
        {
            return this == other;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((EllipticCurveParameters)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = P.GetHashCode();
                hashCode = (hashCode * 397) ^ A.GetHashCode();
                hashCode = (hashCode * 397) ^ B.GetHashCode();
                return hashCode;
            }
        }
    }
}