using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace EllipticCurves.ExtensionsAndHelpers
{
    // Miller-Rabin primality test as an extension method on the BigInteger type.
    // https://rosettacode.org/wiki/Miller%E2%80%93Rabin_primality_test#C.23
    public static class BigIntegerExtensions
    {
        private static BigInteger Q;
        private static int S;
        private static BigInteger Z;

        private static BigInteger quadraticNonResidue(BigInteger P)
        {
            BigInteger z = 0;
            for (BigInteger i = 0; i < P; i++)
            {
                BigInteger check = BigInteger.ModPow(i, (P - 1) / 2, P);
                if (check == (P - 1) || -1 == check)
                {
                    z = i;
                    break;
                }
            }

            return z;
        }

        /// <summary>
        /// Finds Q (odd number) and S such that p-1 = Q2^S and a non quadratic residue Z
        /// </summary>
        /// <param name="P"></param>
        private static void computeQSZ(BigInteger P)
        {
            // 
            BigInteger pMinus1 = P - 1;
            int j = 1;
            bool found = false;
            BigInteger res = 0;
            BigInteger pow2 = 0;
            do
            {
                pow2 = BigInteger.Pow(2, j);
                res = pMinus1 / pow2;
                if (res % 2 != 0)
                {
                    found = true;
                    S = j;
                    Q = res;
                }

                j++;
            } while ((P < pow2) || !found);

            Z = quadraticNonResidue(P);
        }

        public static bool IsProbablePrime(this BigInteger Source, int Certainty)
        {
            if (Source == 2 || Source == 3)
                return true;
            if (Source < 2 || Source % 2 == 0)
                return false;

            BigInteger d = Source - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            // There is no built-in method for generating random BigInteger values.
            // Instead, random BigIntegers are constructed from randomly generated
            // byte arrays of the same length as the source.
            RandomNumberGenerator rng = RandomNumberGenerator.Create();
            byte[] bytes = new byte[Source.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < Certainty; i++)
            {
                do
                {
                    // This may raise an exception in Mono 2.10.8 and earlier.
                    // http://bugzilla.xamarin.com/show_bug.cgi?id=2761
                    rng.GetBytes(bytes);
                    a = new BigInteger(bytes);
                }
                while (a < 2 || a >= Source - 2);

                BigInteger x = BigInteger.ModPow(a, d, Source);
                if (x == 1 || x == Source - 1)
                    continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, Source);
                    if (x == 1)
                        return false;
                    if (x == Source - 1)
                        break;
                }

                if (x != Source - 1)
                    return false;
            }

            return true;
        }

        public static BigInteger BigPow(this BigInteger Source, BigInteger Power)
        {
            BigInteger result = 1;

            var intMaxIterations = Power / int.MaxValue;

            for (BigInteger i = 0; i < intMaxIterations; i++)
            {
                result *= BigInteger.Pow(Source, int.MaxValue);
            }

            var remainder = (int)(Power % int.MaxValue);

            if (remainder > 0) result *= BigInteger.Pow(Source, remainder);

            return result;
        }

        /// <summary>
        /// Finds the inverse mod p
        /// </summary>
        /// <param name="Source"></param>
        /// <param name="P"></param>
        /// <returns></returns>
        public static BigInteger ModInv(this BigInteger Source, BigInteger P)
        {
            BigInteger t = 0;
            BigInteger r = P;
            BigInteger newt = 1;
            BigInteger newr = Source;

            while (0 != newr)
            {
                BigInteger prov;
                BigInteger quot = r / newr;
                prov = newt;
                newt = t - quot * prov;
                t = prov;
                prov = newr;
                newr = r - quot * prov;
                r = prov;
            }
            if (r > 1) // not invertible
                throw new Exception("Not invertible");

            // returns t or t-P if t < 0
            return (t + P) % P;
        }

        /// <summary>
        /// Finds an integer square root r.
        /// The other is -r.
        /// </summary>
        /// <param name="Source"></param>
        /// <returns></returns>
        public static BigInteger Sqrt(this BigInteger Source)
        {
            if (0 == Source) { return 0; }  // Avoid zero divide
            BigInteger n = (Source / 2) + 1;       // Initial estimate, never low
            BigInteger n1 = (n + (Source / n)) / 2;
            while (n1 < n)
            {
                n = n1;
                n1 = (n + (Source / n)) / 2;
            }
            return n;
        }

        /// <summary>
        /// Finds the square root r mod p using the Tonelli-Shanks algorithm.
        /// The other one is -r or p - r.
        /// </summary>
        /// <param name=""></param>
        /// <param name="P"></param>
        /// <param name="CalcParamsQSZ">true</param>
        /// <returns></returns>
        public static BigInteger ModSqrt(this BigInteger Source, BigInteger P, bool CalcParamsQSZ = true)
        {
            // Check whether the number is a quadratic residue (Euler's criterion)
            var check = BigInteger.ModPow(Source, (P - 1) / 2, P);
            if (1 != check)
                throw new Exception($"{Source} is not a quadratic residue");

            if (CalcParamsQSZ)
            {
                CalcParamsQSZ = true;
                computeQSZ(P);
            }

            BigInteger res = 0;
            BigInteger pow2 = 0;

            // compute square root mod p - Tonelli-Shanks algorithm
            var m = S;
            var c = BigInteger.ModPow(Z, Q, P);
            var t = BigInteger.ModPow(Source, Q, P);
            var r = BigInteger.ModPow(Source, (Q + 1) / 2, P);

            while ((t != 0) && (t != 1))
            {
                int k = 0;
                BigInteger tmp = 0;
                while ((k < m) && (tmp != 1))
                {
                    ++k;
                    pow2 = BigInteger.Pow(2, k);
                    tmp = BigInteger.ModPow(t, pow2, P);
                }
                var b1 = BigInteger.ModPow(c, BigInteger.Pow(2, m - k - 1), P);
                m = k;
                c = BigInteger.ModPow(b1, 2, P);
                t = (t * c) % P;
                r = (r * b1) % P;
            }

            return r;
        }

        public static bool Coprime(this BigInteger Source, BigInteger N)
        {
            return 1 == BigInteger.GreatestCommonDivisor(Source, N);
        }

        #region BASE CONVERSION

        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a binary string.
        /// </summary>
        /// <param name="Source">A <see cref="BigInteger"/>.</param>
        /// <returns>
        /// A <see cref="System.String"/> containing a binary
        /// representation of the supplied <see cref="BigInteger"/>.
        /// </returns>
        public static string ToBinaryString(this BigInteger Source)
        {
            var bytes = Source.ToByteArray();
            var idx = bytes.Length - 1;

            // Create a StringBuilder having appropriate capacity.
            var base2 = new StringBuilder(bytes.Length * 8);

            // Convert first byte to binary.
            var binary = Convert.ToString(bytes[idx], 2);

            // Ensure leading zero exists if value is positive.
            if (binary[0] != '0' && Source.Sign == 1)
            {
                base2.Append('0');
            }

            // Append binary string to StringBuilder.
            base2.Append(binary);

            // Convert remaining bytes adding leading zeros.
            for (idx--; idx >= 0; idx--)
            {
                base2.Append(Convert.ToString(bytes[idx], 2).PadLeft(8, '0'));
            }

            return base2.ToString();
        }

        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a hexadecimal string.
        /// </summary>
        /// <param name="Source">A <see cref="BigInteger"/>.</param>
        /// <returns>
        /// A <see cref="System.String"/> containing a hexadecimal
        /// representation of the supplied <see cref="BigInteger"/>.
        /// </returns>
        public static string ToHexadecimalString(this BigInteger Source)
        {
            return Source.ToString("X");
        }

        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a octal string.
        /// </summary>
        /// <param name="Source">A <see cref="BigInteger"/>.</param>
        /// <returns>
        /// A <see cref="System.String"/> containing an octal
        /// representation of the supplied <see cref="BigInteger"/>.
        /// </returns>
        public static string ToOctalString(this BigInteger Source)
        {
            var bytes = Source.ToByteArray();
            var idx = bytes.Length - 1;

            // Create a StringBuilder having appropriate capacity.
            var base8 = new StringBuilder(((bytes.Length / 3) + 1) * 8);

            // Calculate how many bytes are extra when byte array is split
            // into three-byte (24-bit) chunks.
            var extra = bytes.Length % 3;

            // If no bytes are extra, use three bytes for first chunk.
            if (extra == 0)
            {
                extra = 3;
            }

            // Convert first chunk (24-bits) to integer value.
            int int24 = 0;
            for (; extra != 0; extra--)
            {
                int24 <<= 8;
                int24 += bytes[idx--];
            }

            // Convert 24-bit integer to octal without adding leading zeros.
            var octal = Convert.ToString(int24, 8);

            // Ensure leading zero exists if value is positive.
            if (octal[0] != '0' && Source.Sign == 1)
            {
                base8.Append('0');
            }

            // Append first converted chunk to StringBuilder.
            base8.Append(octal);

            // Convert remaining 24-bit chunks, adding leading zeros.
            for (; idx >= 0; idx -= 3)
            {
                int24 = (bytes[idx] << 16) + (bytes[idx - 1] << 8) + bytes[idx - 2];
                base8.Append(Convert.ToString(int24, 8).PadLeft(8, '0'));
            }

            return base8.ToString();
        }

        /// <summary>
        /// Converts a <see cref="BinaryString"/> to a big integer.
        /// </summary>
        /// <param name="Source">A <see cref="BigInteger"/>.</param>
        /// <returns>
        /// A <see cref="BigInteger"/> from a binary
        /// representation of the supplied <see cref="System.String"/>.
        /// </returns>
        public static BigInteger BinaryStringToDecimal(string BinaryValue)
        {
            BigInteger Source = 0;

            foreach (char bit in BinaryValue)
            {
                Source <<= 1;
                Source += bit == '1' ? 1 : 0;
            }

            return Source;
        }

        /// <summary>
        /// Converts a <see cref="HexdecimalString"/> to a big integer.
        /// </summary>
        /// <param name="Source">A <see cref="BigInteger"/>.</param>
        /// <returns>
        /// A <see cref="BigInteger"/> from a hexadecimal
        /// representation of the supplied <see cref="System.String"/>.
        /// </returns>
        public static BigInteger HexadecimalStringToDecimal(string HexValue)
        {
            BigInteger Source = BigInteger.Parse(HexValue, NumberStyles.AllowHexSpecifier);

            return Source;
        }

        #endregion

        #region RANDOM GENERATOR

        /// <summary>
        /// Generates a random positive BigInteger between 0 and 2^bitLength (non-inclusive).
        /// </summary>
        /// <param name="bitLength">The number of random bits to generate.</param>
        /// <returns>A random positive BigInteger between 0 and 2^bitLength (non-inclusive).</returns>
        public static BigInteger NextBigInteger(int bitLength, int Seed = 0)
        {
            if (bitLength < 1) return BigInteger.Zero;

            int bytes = bitLength / 8;
            int bits = bitLength % 8;

            // Generates enough random bytes to cover our bits.
            byte[] bs = new byte[bytes + 1];
            Random rnd = 0 == Seed ? new Random() : new Random(Seed);
            rnd.NextBytes(bs);

            // Mask out the unnecessary bits.
            byte mask = (byte)(0xFF >> (8 - bits));
            bs[bs.Length - 1] &= mask;

            return new BigInteger(bs);
        }

        /// <summary>
        /// Generates a random BigInteger between start and end (non-inclusive).
        /// </summary>
        /// <param name="start">The lower bound.</param>
        /// <param name="end">The upper bound (non-inclusive).</param>
        /// <returns>A random BigInteger between start and end (non-inclusive)</returns>
        public static BigInteger NextBigInteger(BigInteger start, BigInteger end)
        {
            if (start == end) return start;

            BigInteger res = end;

            // Swap start and end if given in reverse order.
            if (start > end)
            {
                end = start;
                start = res;
                res = end - start;
            }
            else
                // The distance between start and end to generate a random BigIntger between 0 and (end-start) (non-inclusive).
                res -= start;

            byte[] bs = res.ToByteArray();

            // Count the number of bits necessary for res.
            int bits = 8;
            byte mask = 0x7F;
            while ((bs[bs.Length - 1] & mask) == bs[bs.Length - 1])
            {
                bits--;
                mask >>= 1;
            }
            bits += 8 * bs.Length;

            // Generate a random BigInteger that is the first power of 2 larger than res, 
            // then scale the range down to the size of res,
            // finally add start back on to shift back to the desired range and return.
            return ((NextBigInteger(bits + 1) * res) / BigInteger.Pow(2, bits + 1)) + start;
        }

        #endregion

    }
}

