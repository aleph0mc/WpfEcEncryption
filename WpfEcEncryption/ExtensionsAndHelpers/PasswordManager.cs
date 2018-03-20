using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;


namespace EllipticCurves.ExtensionsAndHelpers
{
    public class HashWithSaltResult
    {
        public string Salt { get; }
        public string Digest { get; set; }

        public HashWithSaltResult(string salt, string digest)
        {
            Salt = salt;
            Digest = digest;
        }
    }

    public static class PasswordManager
    {
        public static string GenerateRandomCryptographicKey(int KeyLength)
        {
            return Convert.ToBase64String(GenerateRandomCryptographicBytes(KeyLength));
        }

        public static byte[] GenerateRandomCryptographicBytes(int KeyLength)
        {
            RNGCryptoServiceProvider rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            byte[] randomBytes = new byte[KeyLength];
            rngCryptoServiceProvider.GetBytes(randomBytes);
            return randomBytes;
        }

        public static int Strength(string Password)
        {
            var res = new Zxcvbn.Zxcvbn().EvaluatePassword(Password);
            return (int)res.Entropy;
        }

        public static string Hash(string Password, HashAlgorithm HashAlgo)
        {
            byte[] passwordAsBytes = Encoding.UTF8.GetBytes(Password);
            byte[] hashBytes = HashAlgo.ComputeHash(passwordAsBytes);
            return Convert.ToBase64String(hashBytes);
        }

        public static HashWithSaltResult HashWithSalt(string Password, int SaltLength, HashAlgorithm HashAlgo)
        {
            byte[] saltBytes = GenerateRandomCryptographicBytes(SaltLength);
            byte[] passwordAsBytes = Encoding.UTF8.GetBytes(Password);
            List<byte> passwordWithSaltBytes = new List<byte>();
            passwordWithSaltBytes.AddRange(passwordAsBytes);
            passwordWithSaltBytes.AddRange(saltBytes);
            byte[] digestBytes = HashAlgo.ComputeHash(passwordWithSaltBytes.ToArray());
            return new HashWithSaltResult(Convert.ToBase64String(saltBytes), Convert.ToBase64String(digestBytes));
        }

    }
}
