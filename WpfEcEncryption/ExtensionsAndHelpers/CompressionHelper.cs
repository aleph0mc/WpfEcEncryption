using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EllipticCurves.ExtensionsAndHelpers
{
    public class CompressionHelper
    {
        private static void CopyTo(Stream src, Stream dest)
        {
            byte[] bytes = new byte[4096];

            int cnt;

            while ((cnt = src.Read(bytes, 0, bytes.Length)) != 0)
                dest.Write(bytes, 0, cnt);
        }

        /// <summary>
        /// Convert BitArray to Byte Array
        /// </summary>
        /// <param name="Source"></param>
        /// <returns></returns>
        private static byte[] bitArrayToByteArray(BitArray Source)
        {
            var bytes = new byte[Source.Count / 8];
            Source.CopyTo(bytes, 0);

            return bytes;
        }

        /// <summary>
        /// Compress a string (default) or a file (isFile = true) and return a BitArray. The Content contains the string or the file full path.
        /// </summary>
        /// <param name="Content"></param>
        /// <param name="IsFile"></param>
        /// <returns></returns>
        public static BitArray Zip(string Content, bool IsFile = false)
        {
            byte[] bytes;

            bytes = IsFile ? File.ReadAllBytes(Content) : Encoding.UTF8.GetBytes(Content);

            using (var msi = new MemoryStream(bytes))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(mso, CompressionMode.Compress))
                {
                    CopyTo(msi, gs);
                    gs.Close();
                }
                return new BitArray(mso.ToArray());
            }
        }

        /// <summary>
        /// Decompress a string (default) and a file (isFile = true) and return the string "Copied".
        /// </summary>
        /// <param name="Bits"></param>
        /// <param name="IsFile"></param>
        /// <param name="FilePath"></param>
        /// <returns></returns>
        public static string Unzip(BitArray Bits, bool IsFile = false, string FilePath = null)
        {
            byte[] bytes = new byte[Bits.Length / 8];
            Bits.CopyTo(bytes, 0);
            using (var msi = new MemoryStream(bytes))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                {
                    CopyTo(gs, mso);
                    gs.Close();
                }
                if (IsFile)
                {
                    //write to file
                    FileStream file = new FileStream(FilePath, FileMode.Create, FileAccess.Write);
                    mso.WriteTo(file);
                    file.Close();

                    return "Copied";
                }

                return Encoding.UTF8.GetString(mso.ToArray());
            }
        }

        /// <summary>
        /// Compress a string to a Base64 string
        /// </summary>
        /// <param name="Content"></param>
        /// <returns></returns>
        public static string ZipBase64String(string Content)
        {
            var bytes = bitArrayToByteArray(Zip(Content));
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Decompress a Base64 string to a string
        /// </summary>
        /// <param name="ContentBase64"></param>
        /// <returns></returns>
        public static string UnzipBase64String(string ContentBase64)
        {
            var bytes = Convert.FromBase64String(ContentBase64);
            var ba = new BitArray(bytes);

            return Unzip(ba);
        }

        /// <summary>
        /// Compress a string to a Base65536 hexadecimal string
        /// </summary>
        /// <param name="Content"></param>
        /// <returns></returns>
        public static string ZipBase65536HexStringBase64(string Content)
        {
            // First compression
            var bytes = bitArrayToByteArray(Zip(Content));

            var ushorts = bytes.ToUShortArray();
            var bi = Base65536Helper.FromArray(ushorts);

            // Second compression
            bytes = bitArrayToByteArray(Zip(bi.ToHexadecimalString()));

            return Convert.ToBase64String(bytes);
        }

        public static string UnzipBase65536HexStringBase64(string HexStringBase65536)
        {
            var bytes = Convert.FromBase64String(HexStringBase65536);

            // First decompression
            var ba = new BitArray(bytes);
            var hexStr = Unzip(ba);

            var bi = BigIntegerExtensions.HexadecimalStringToDecimal(hexStr);
            var ushorts = Base65536Helper.ToArray(bi);
            bytes = ushorts.ToByteArray();
            // Second decompression
            ba = new BitArray(bytes);

            return Unzip(ba);

        }

    }
}
