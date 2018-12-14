using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using System.Threading.Tasks;

namespace ECDSA
{
    static class Utility
    {
        public static int HexToNumber(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
            if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
            return -1;
        }

        public static BigInteger ParseHex(string s)
        {
            var ret = new BigInteger();
            foreach (var c in s)
            {
                var n = HexToNumber(c);
                if (n < 0)
                    continue;
                ret *= 16;
                ret += n;
            }
            return ret;
        }

        public static BigInteger LegendreOperation(this BigInteger a, BigInteger b)
        {
            return BigInteger.ModPow(a, (b - 1)/2, b);
        }

        public static Tuple<BigInteger, BigInteger> TonelliShanks(this BigInteger a, BigInteger n)
        {
            if (a.LegendreOperation(n) != 1)
                return null;

            var n1 = n - 1;
            var q = n1;
            var s = new BigInteger();
            while (q.IsEven)
            {
                q >>= 1;
                s++;
            }

            if (s == 1)
            {
                var temp = BigInteger.ModPow(a, (n + 1) / 4, n);
                return new Tuple<BigInteger, BigInteger>(temp, (-temp).Mod(n));
            }

            var z = new BigInteger(2);
            while (BigInteger.ModPow(z, n1 / 2, n) != n1)
                z++;

            var c = BigInteger.ModPow(z, q, n);
            var r = BigInteger.ModPow(a, (q + 1)/2, n);
            var t = BigInteger.ModPow(a, q, n);
            var m = s;
            while (t.Mod(n) != 1)
            {
                var i = new BigInteger();
                var m2 = m - 1;
                for (var z2 = t; z2 != 1 && i < m2; i++)
                    z2 = z2 * z2 % n;
                var b = c;
                
                for (var e = m - i - 1; e > 0; e--)
                    b = b * b % n;

                r = r * b % n;
                c = b * b % n;
                t = t * c % n;
                m = i;
            }
            return new Tuple<BigInteger, BigInteger>(r, (n - r) % n);
        }

        public static BigInteger ExtendedEuclidean(this BigInteger a, BigInteger b)
        {
            if (b.Sign < 0)
                b = -b;
            if (a.Sign < 0)
                a = a.Mod(b);
            BigInteger x0 = 1;
            BigInteger x1 = 0;
            var b2 = b;
            while (!b2.IsZero)
            {
                BigInteger remainder;
                var q = BigInteger.DivRem(a, b2, out remainder);
                a = b2;
                b2 = remainder;

                var temp = x0;
                x0 = x1;
                x1 = temp - q*x0;
            }

            return x0.Mod(b);
        }

        public static BigInteger Mod(this BigInteger a, BigInteger b)
        {
            if (a.Sign < 0)
                return (a%b + b) % b;
            return a%b;
        }
    }
}
