using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;

namespace EllipticCurves.ExtensionsAndHelpers
{
    public static class Base65536Helper
    {
        private const int BASE65536 = 65536;

        /// <summary>
        /// Convert a BigInteger base 65536 to an array of short base 65536 (bigendian)
        /// </summary>
        /// <param name="Num"></param>
        /// <returns></returns>
        public static ushort[] ToArray(BigInteger Num)
        {
            BigInteger quotient = Num;
            List<ushort> values = new List<ushort>();
            while (0 < quotient)
            {
                ushort unicodeChar = (ushort)(quotient % BASE65536);
                values.Add(unicodeChar);
                quotient /= BASE65536;
            }
            values.Reverse();   
            return values.ToArray();
        }

        /// <summary>
        /// Convert a ushort array to a big integer base 65536 (bigendian)
        /// </summary>
        /// <param name="ArrShort"></param>
        /// <returns></returns>
        public static BigInteger FromArray(ushort[] ArrShort)
        {
            BigInteger ret = 0;
            int pow = ArrShort.Length - 1;
            for (int i = 0; i <= pow; i++)
                ret += ArrShort[i] * BigInteger.Pow(BASE65536, pow - i);

            return ret;
        }
    }
}
