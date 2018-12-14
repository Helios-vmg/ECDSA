using System;
using System.Diagnostics;
using System.Numerics;

namespace ECDSA
{
    public class EcPoint
    {
        public BigInteger X = 0, Y = 0;
        private EllipticCurveParameters _params;
        private bool _infinite = false;

        //private BigInteger A => _params.A;
        //private BigInteger B => _params.B;
        //private BigInteger P => _params.P;

        public static EcPoint Infinity = new EcPoint();

        private EcPoint()
        {
            _infinite = true;
        }

        public EcPoint(BigInteger x, BigInteger y, EllipticCurveParameters param)
        {
            X = x;
            Y = y;
            _params = param;
        }

        public EcPoint(string s, EllipticCurveParameters param)
        {
            _params = param;
            byte firstByte = 0;
            int i = 0;
            int j = 0;
            for (; j < s.Length && i < 2; j++)
            {
                var n = Utility.HexToNumber(s[j]);
                if (n < 0)
                    continue;
                firstByte = (byte) ((firstByte << 4) | n);
                i++;
            }
            if (i < 2)
                throw new Exception();
            if (firstByte != 4)
            {
                X = Utility.ParseHex(s.Substring(j));
                var y = EvaluateX().TonelliShanks(_params.P);
                if (firstByte%2 == y.Item1%2)
                    Y = y.Item1;
                else
                    Y = y.Item2;
            }
            else
            {
                int k = 0;
                for (; j < s.Length && k < 64; j++)
                {
                    var n = Utility.HexToNumber(s[j]);
                    if (n < 0)
                        continue;
                    X <<= 16;
                    X += n;
                    k++;
                }
                if (k < 64)
                    throw new Exception();
                k = 0;
                for (; j < s.Length && k < 64; j++)
                {
                    var n = Utility.HexToNumber(s[j]);
                    if (n < 0)
                        continue;
                    Y <<= 16;
                    Y += n;
                    k++;
                }
                if (k < 64)
                    throw new Exception();
            }
        }

        private BigInteger EvaluateX()
        {
            return _params.EvaluateX(X);
        }

        public bool IsInfinite => _infinite;

        private bool SameCurve(EcPoint b)
        {
            return IsInfinite || b.IsInfinite || _params == b._params;
        }

        public bool IsSolution()
        {
            return IsInfinite || _params.IsSolution(X, Y);
        }

        private BigInteger? Slope()
        {
            return _params.GetSlope(X, Y);
        }

        public static bool operator ==(EcPoint a, EcPoint b)
        {
            if (a.IsInfinite)
                return b.IsInfinite;
            if (b.IsInfinite)
                return false;
            return a.SameCurve(b) && a.X == b.X && a.Y == b.Y;
        }

        public static bool operator !=(EcPoint a, EcPoint b)
        {
            return !(a == b);
        }

        public static EcPoint operator +(EcPoint a, EcPoint b)
        {
            if (a.IsInfinite)
                return b.IsInfinite ? Infinity : b;
            if (b.IsInfinite)
                return a;

            if (!a.SameCurve(b))
                throw new Exception();
            if (!a.IsSolution() || !b.IsSolution())
                throw new Exception();

            BigInteger coeff1;
            var p = a._params.P;
            if (a == b)
            {
                var s = a.Slope();
                if (s == null)
                    return Infinity;
                coeff1 = s.Value;
            }
            else
            {
                if (a.X == b.X)
                    return Infinity;
                if (a.X > b.X)
                {
                    var temp = a;
                    a = b;
                    b = temp;
                }
                coeff1 = ((b.Y - a.Y) * (b.X - a.X).ExtendedEuclidean(p)).Mod(p);
            }
            var coeff0 = (a.Y - coeff1 * a.X).Mod(p);
            Debug.Assert((coeff1 * a.X + coeff0).Mod(p) == a.Y);
            Debug.Assert((coeff1 * b.X + coeff0).Mod(p) == b.Y);
            var x = (coeff1 * coeff1 - a.X - b.X).Mod(p);
            var y = (-(coeff1 * x + coeff0)).Mod(p);

            var ret = new EcPoint(x, y, a._params);
            Debug.Assert(ret.IsSolution());
            return ret;
        }

        public static EcPoint operator -(EcPoint a)
        {
            if (a.IsInfinite)
                return a;
            return new EcPoint(a.X, (-a.Y).Mod(a._params.P), a._params);
        }
        
        private static int BitSize(byte n)
        {
            for (int i = 0; i < 8; i++)
                if (n >> i == 0)
                    return i;
            return 8;
        }

        private static int LastByte(byte[] a)
        {
            int ret = -1;
            for (int i = 0; i < a.Length; i++)
                if (a[i] != 0)
                    ret = i;
            return ret;
        }

        private static int CountBits(byte[] a)
        {
            var bytes = LastByte(a);
            return bytes*8 + BitSize(a[bytes]);
        }

        public static EcPoint operator *(EcPoint a, BigInteger n)
        {
            if (n.IsZero)
                return Infinity;
            if (n.Sign < 0)
                return -(a*-n);

            var bytes = n.ToByteArray();
            var m = CountBits(bytes);

            EcPoint ret = Infinity;
            for (int i = 0; i < m; i++)
            {
                var bit = (bytes[i / 8] >> (i % 8)) & 1;
                if (bit != 0)
                    ret += a;
                a += a;
            }
            return ret;
        }

        public static EcPoint FromX(BigInteger x, bool positiveY, EllipticCurveParameters param)
        {
            var ret = new EcPoint(x, 0, param);
            var sols = ret.EvaluateX().TonelliShanks(param.P);
            if (sols == null)
                return null;
            if (positiveY == (sols.Item1 <= param.P/2))
                ret.Y = sols.Item1;
            else
                ret.Y = sols.Item2;
            return ret;
        }

        protected bool Equals(EcPoint other)
        {
            return this == other;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((EcPoint)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = X.GetHashCode();
                hashCode = (hashCode * 397) ^ Y.GetHashCode();
                hashCode = (hashCode * 397) ^ (_params != null ? _params.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ _infinite.GetHashCode();
                return hashCode;
            }
        }
    }
}