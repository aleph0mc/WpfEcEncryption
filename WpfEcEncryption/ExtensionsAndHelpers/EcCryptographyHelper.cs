using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text;
using Newtonsoft.Json;

namespace EllipticCurves.ExtensionsAndHelpers
{
    public class EcModPoint
    {
        public BigInteger x { get; set; }
        public BigInteger y { get; set; }
        public bool IsInf { get; set; }
        public BigInteger OrderN { get; set; }
    }

    public static class EcCryptographyHelper
    {
        #region CONSTANTS FOR CURVE sec256k1

        private static readonly BigInteger SEC256K1_P = BigInteger.Parse("115792089237316195423570985008687907853269984665640564039457584007908834671663");
        private static readonly BigInteger SEC256K1_N = BigInteger.Parse("115792089237316195423570985008687907852837564279074904382605163141518161494337");
        private static readonly EcModPoint SEC256K1_G = new EcModPoint
        {
            x = BigInteger.Parse("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
            y = BigInteger.Parse("32670510020758816978083085130507043184471273380659243275938904335757337482424")
        };

        #endregion

        #region ELLIPTIC CURVE KEY PAIR GENERATOR

        private static EcModPoint pointAdd(EcModPoint pointP, EcModPoint pointQ, BigInteger a, BigInteger p)
        {
            // compute m = (y1 - y0) / (x1 - x0) (mod p)
            var x0 = pointP.x;
            var y0 = pointP.y;

            var x1 = pointQ.x;
            var y1 = pointQ.y;

            // compute m mod p
            BigInteger dy = (y1 - y0) % p;
            BigInteger dx = (x1 - x0) % p;
            dy = (dy + p) % p;
            dx = (dx + p) % p;

            BigInteger inv_dx = dx.ModInv(p);
            BigInteger m = BigInteger.Multiply(dy, inv_dx) % p;
            m = (m + p) % p;

            var x = (m * m - x0 - x1) % p;
            x = (x + p) % p;
            var y = (m * (x0 - x) - y0) % p;  //(-m * m * m + 3 * m * x0 - y0) % p;
            y = (y + p) % p;

            EcModPoint ret = new EcModPoint { x = x, y = y };
            return ret;

        }

        private static EcModPoint pointDouble(EcModPoint point, BigInteger a, BigInteger p)
        {
            // compute m = dy/dx = dy * dx^-1 (mod p)
            var x0 = point.x;
            var y0 = point.y;

            BigInteger dy = (3 * x0 * x0 + a) % p;
            BigInteger dx = (2 * y0) % p;
            dy = (dy + p) % p;
            dx = (dx + p) % p;

            // compute inverse of dx mod p
            BigInteger inv_dx = dx.ModInv(p);

            // compute m mod p
            BigInteger m = BigInteger.Multiply(dy, inv_dx) % p;
            m = (m + p) % p;

            var x = (m * m - 2 * x0) % p;
            x = (x + p) % p;
            var y = (m * (x0 - x) - y0) % p;  //(-m * m * m + 3 * m * x0 - y0) % p;
            y = (y + p) % p;

            EcModPoint ret = new EcModPoint { x = x, y = y };
            return ret;
        }

        private static EcModPoint computeECPointMultiply(BigInteger a, EcModPoint g, BigInteger p, BigInteger sk)
        {
            var bitString = sk.ToBinaryString();
            EcModPoint q = g;
            foreach (var bit in bitString)
            {
                q = pointDouble(q, a, p);
                if (bit == '1')
                    q = pointAdd(q, g, a, p);
            }

            return q;

        }

        private static EcModPoint computePointSum(BigInteger a, EcModPoint pointP, EcModPoint pointQ, BigInteger p)
        {
            BigInteger x2 = 0;
            BigInteger y2 = 0;
            BigInteger m = 0;
            EcModPoint ret = null;

            if (null == pointQ) // P1 = P0, P2 = P0 + P1 = 2P0
                ret = pointDouble(pointP, a, p);
            else // P2 = P0 + P1
                ret = pointAdd(pointP, pointQ, a, p);

            return ret;
        }

        /// <summary>
        /// Returns the key pair
        /// </summary>
        /// <param name="P"></param>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <param name="G"></param>
        /// <param name="N"></param>
        /// <param name="SecretKey"></param>
        /// <returns></returns>
        public static EcModPoint ECKeyPairGenerator(BigInteger P, BigInteger A, BigInteger B, EcModPoint G, BigInteger N, BigInteger SecretKey)
        {
            // If private key Sk is not in the range 0 < Sk < N (order of G) then error
            if (SecretKey < 1 || SecretKey >= N)
                throw new Exception("Private key is not in the range.");

            // Check the discriminant for the eliptic curve y^2 = x^3 + a*x + b: -16(4a^3 + 27b^2) != 0
            var delta = 4 * A * A * A + 27 * B * B;
            if (0 == delta)
                throw new Exception("Delta cannot be zero.");

            return computeECPointMultiply(A, G, P, SecretKey);
        }

        /// <summary>
        /// Return point Q coords representing public key pair (see specs for secp256k1 parameters)
        /// </summary>
        /// <returns></returns>
        public static EcModPoint SecP256k1KeyPairGenerator(BigInteger Sk)
        {
            // Elliptic curve equation: y^2 = x^3 + a*x + b => y^2 = x^3 + 7
            var a = 0;
            var b = 7;
            return ECKeyPairGenerator(SEC256K1_P, a, b, SEC256K1_G, SEC256K1_N, Sk);
        }

        /// <summary>
        /// Returns the final point via summation. This method is very slow. Do not use big value for Sk.
        /// </summary>
        /// <param name="A"></param>
        /// <param name="B"></param>
        /// <param name="G"></param>
        /// <param name="Sk"></param>
        /// <returns></returns>
        public static EcModPoint EcSlowKeyPairGeneratorByClassicPointSum(BigInteger P, BigInteger A, BigInteger B, EcModPoint G, int Sk)
        {
            var delta = 4 * A * A * A + 27 * B * B;
            if (0 == delta)
                throw new Exception("Delta cannot be zero.");

            int cnt = 2;
            bool inf = false;
            EcModPoint qMod = null;
            while (cnt <= Sk && !inf)
            {
                qMod = computePointSum(A, G, qMod, P);
                inf = G.x == qMod.x;
                if (inf)
                {
                    qMod.IsInf = true;
                    qMod.OrderN = cnt;
                }
                ++cnt;
            }

            return qMod;
        }

        /// <summary>
        /// Returns the list of points by addition (P + Q). This method is very slow. Do not use big value for Sk.
        /// </summary>
        /// <param name="P"></param>
        /// <param name="A"></param>
        /// <param name="B></param>
        /// <param name="G"></param>
        /// <param name="Sk"></param>
        /// <returns></returns>
        public static List<EcModPoint> EcSlowPointListByAddition(BigInteger P, BigInteger A, BigInteger B, EcModPoint G, int Sk)
        {
            var delta = 4 * A * A * A + 27 * B * B;
            if (0 == delta)
                throw new Exception("Delta cannot be zero.");

            var ret = new List<EcModPoint>();
            ret.Add(G);
            int cnt = 2;
            bool inf = false;
            EcModPoint qMod = null;
            while (cnt <= Sk && !inf)
            {
                qMod = computePointSum(A, G, qMod, P);
                inf = G.x == qMod.x;
                if (inf)
                {
                    qMod.IsInf = true;
                    qMod.OrderN = cnt;
                }
                ret.Add(qMod);
                ++cnt;
            }

            return ret;
        }

        #endregion

        /// <summary>
        /// Encrypt text on curve secP256k1 and return a list of points on the elliptic curve
        /// </summary>
        /// <param name="Text"></param>
        /// <param name="PubKey"></param>
        /// <returns></returns>
        public static List<EcModPoint> EncryptSecP256k1(string Text, EcModPoint PubKey)
        {
            // return the digits of P base 65536
            ushort[] digits = Base65536Helper.ToArray(SEC256K1_P);
            var partitionLen = digits.Length - 1;

            // return a string array with string spit in groups of digits
            var partitionStrings = Text.SplitInGroup(partitionLen);

            // 1) create a list of big integers out of partitioned message
            List<BigInteger> lstBiMsg = new List<BigInteger>();
            foreach (var partitionStr in partitionStrings)
            {
                // encode the partioned str in Unicode
                var encUtf8 = Encoding.Unicode.GetBytes(partitionStr);
                // convert to ushort array
                var arrShort = encUtf8.ToUShortArray();
                // convert to bae 65536 big integer
                var bi65536 = Base65536Helper.FromArray(arrShort);
                // add to the list
                lstBiMsg.Add(bi65536);
            }

            // 2) pair with ascii 32 (space) if list count is odd
            var lstCnt = lstBiMsg.Count;
            if (0 != lstCnt % 2)
            {
                lstBiMsg.Add(32);
                lstCnt++;
            }
            // 3) build the pairs
            List<EcModPoint> lstPm = new List<EcModPoint>();
            for (int i = 0; i < lstCnt; i += 2)
            {
                var pnt = new EcModPoint { x = lstBiMsg[i], y = lstBiMsg[i + 1] };
                lstPm.Add(pnt);
            }

            // get a random big integer k
            var k = BigIntegerExtensions.NextBigInteger(185, DateTime.Now.Millisecond);
            // 4) compute k*G for curve secP256k1
            var kG = SecP256k1KeyPairGenerator(k);

            // 5) compute kPb = k(SkG)
            var kPb = ECKeyPairGenerator(SEC256K1_P, 0, 7, PubKey, SEC256K1_N, k);

            // 6) compute Pm + kPb = Pc (encrypted data)
            List<EcModPoint> lstEncr = new List<EcModPoint>();
            // first row is kG
            lstEncr.Add(kG);
            foreach (var pnt in lstPm)
            {
                // a = 0 for secP256k1
                var pntAdded = pointAdd(pnt, kPb, 0, SEC256K1_P);
                lstEncr.Add(pntAdded);
            }

            return lstEncr;
        }

        /// <summary>
        /// Encrypt text on curve secP256k1 and return a list of points on the elliptic curve in Json format (string)
        /// </summary>
        /// <param name="Text"></param>
        /// <param name="PubKey"></param>
        /// <returns></returns>
        public static string EncryptSecP256k1Json(string Text, EcModPoint PubKey)
        {
            var lstEncr = EncryptSecP256k1(Text, PubKey);
            var json = JsonConvert.SerializeObject(lstEncr);

            return json;

        }

        /// <summary>
        /// Dencrypt text on curve secP256k1 and return the message
        /// </summary>
        /// <param name="LstEncr"></param>
        /// <param name="SecretKey"></param>
        /// <returns></returns>
        public static string DecryptSecP256k1(List<EcModPoint> LstEncr, BigInteger SecretKey)
        {
            // 1) get kG
            var kG = LstEncr.First();
            // 2) compute kPb = k(SkG) = Sk(kG)
            var kPb = ECKeyPairGenerator(SEC256K1_P, 0, 7, kG, SEC256K1_N, SecretKey);
            // set -kPb
            var negkPb = new EcModPoint { x = kPb.x, y = -kPb.y };

            // remove kG from the list
            LstEncr.RemoveAt(0);

            // 3) decrypt - compute Pc - kPb = Pm (plain message)
            var strMsg = string.Empty;
            foreach (var pnt in LstEncr)
            {
                var decPnt = pointAdd(pnt, negkPb, 0, SEC256K1_P);
                // data from x coord
                var arrUShort = Base65536Helper.ToArray(decPnt.x);
                var bytes = arrUShort.ToByteArray();
                var str = Encoding.Unicode.GetString(bytes);
                strMsg = string.Concat(strMsg, str);
                // data from y coord
                arrUShort = Base65536Helper.ToArray(decPnt.y);
                bytes = arrUShort.ToByteArray();
                str = Encoding.Unicode.GetString(bytes);
                strMsg = string.Concat(strMsg, str);
            }

            return strMsg;
        }

        /// <summary>
        /// Decrypt text on curve secP256k1 using the list of points on the elliptic curve in Json format (string)
        /// </summary>
        /// <param name="JsonCrypt"></param>
        /// <param name="SecretKey"></param>
        /// <returns></returns>
        public static string DecryptSecP256k1Json(string JsonCrypt, BigInteger SecretKey)
        {
            var deserLst = JsonConvert.DeserializeObject<List<EcModPoint>>(JsonCrypt);
            var msg = DecryptSecP256k1(deserLst, SecretKey);
            return msg;
        }
    }
}
