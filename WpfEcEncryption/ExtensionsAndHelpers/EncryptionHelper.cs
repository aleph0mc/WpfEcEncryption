using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace EllipticCurves.ExtensionsAndHelpers
{
    public static class EncryptionHelper
    {
        private static string _keyRepoPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "KeyRepo");

        private static void createKeyRepo()
        {
            if (!Directory.Exists(_keyRepoPath))
                Directory.CreateDirectory(_keyRepoPath);
        }

        private static void saveXmlKey(string RepoFileName, string RsaKey, bool CreateNewKeyFile = false)
        {
            var xmlPathFile = Path.Combine(_keyRepoPath, RepoFileName);
            if (!File.Exists(xmlPathFile) || (File.Exists(xmlPathFile) && CreateNewKeyFile))
                using (FileStream fs = new FileStream(xmlPathFile, FileMode.Create, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.Write(RsaKey);
                    sw.Flush();
                }
        }

        /// <summary>
        /// Assign new key pair and save in the folder MyDocument\KeyRepo
        /// </summary>
        public static void AssignNewRsaKeyAndSaveXml()
        {
            string publicPrivateKeyXML;
            string publicOnlyKeyXML;

            const int PROVIDER_RSA_FULL = 1;
            const string CONTAINER_NAME = "KeyContainer";
            CspParameters cspParams;
            cspParams = new CspParameters(PROVIDER_RSA_FULL);
            cspParams.KeyContainerName = CONTAINER_NAME;
            //cspParams.Flags = CspProviderFlags.UseMachineKeyStore;
            //cspParams.ProviderName = "Microsoft Strong Cryptographic Provider";
            var rsa = new RSACryptoServiceProvider(cspParams);

            // Create the key repo if it doesn't exists
            createKeyRepo();

            // Pair of public and private key as XML string.
            // Do not share this to other party
            publicPrivateKeyXML = rsa.ToXmlString(true);

            // Save all key to xml file if required
            saveXmlKey("AllKeys.xml", publicPrivateKeyXML);

            // Public key in xml file, this xml should be shared to other parties
            publicOnlyKeyXML = rsa.ToXmlString(false);

            // Save public key to xml file if required
            saveXmlKey("Public.xml", publicOnlyKeyXML);

        }

        /// <summary>
        /// Encrypt the symmetric key using RSA and return a byte array
        /// </summary>
        /// <param name="Data2Encrypt"></param>
        /// <returns></returns>
        private static byte[] encryptRsa4SymKey(byte[] Data2Encrypt)
        {
            string publicKeyXML;
            using (var reader = new StreamReader(Path.Combine(_keyRepoPath, "Public.xml")))
            {
                publicKeyXML = reader.ReadToEnd();
            }

            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicKeyXML);
            var bytes = Data2Encrypt;
            return rsa.Encrypt(bytes, true);
        }

        /// <summary>
        /// Decrypt a byte array to the original string
        /// </summary>
        /// <param name="Data2Decrypt"></param>
        /// <returns></returns>
        private static byte[] decryptRsa4SymKey(byte[] Data2Decrypt)
        {
            string publicPrivateKeyXML;
            using (var reader = new StreamReader(Path.Combine(_keyRepoPath, "AllKeys.xml")))
            {
                publicPrivateKeyXML = reader.ReadToEnd();
            }

            var rsa = new RSACryptoServiceProvider();
            rsa.FromXmlString(publicPrivateKeyXML);

            return rsa.Decrypt(Data2Decrypt, true);
        }

        /// <summary>
        /// Encrypt an array of bytes (adapted from http://pages.infinit.net/ctech/20031101-0151.html)
        /// </summary>
        /// <param name="Buff"></param>
        /// <returns></returns>
        public static byte[] Encrypt(byte[] Buff)
        {
            // Create a 128 bits AES key
            var symAlgo = SymmetricAlgorithm.Create();
            ICryptoTransform cryptoTran = symAlgo.CreateEncryptor();
            // Sym key encryption
            byte[] encrypt = cryptoTran.TransformFinalBlock(Buff, 0, Buff.Length);
            // Encrypt sym key using RSA
            byte[] RSAedKey = encryptRsa4SymKey(symAlgo.Key);

            // Add up the symmetric key encrypted with RSA, the IV (initialization vector) and encrypted data using the symmetric key
            var bytes = new byte[RSAedKey.Length + symAlgo.IV.Length + encrypt.Length];
            Buffer.BlockCopy(RSAedKey, 0, bytes, 0, RSAedKey.Length);
            Buffer.BlockCopy(symAlgo.IV, 0, bytes, RSAedKey.Length, symAlgo.IV.Length);
            Buffer.BlockCopy(encrypt, 0, bytes, RSAedKey.Length + symAlgo.IV.Length, encrypt.Length);
            return bytes;
        }

        /// <summary>
        /// Encrypt text and return Base64 string
        /// </summary>
        /// <param name="Data2Encrypt"></param>
        /// <returns></returns>
        public static string EncryptToBase64String(string Data2Encrypt)
        {
            var bytes = Encoding.ASCII.GetBytes(Data2Encrypt);
            return Convert.ToBase64String(Encrypt(bytes));
        }

        /// <summary>
        /// Encrypt text and return BigInteger in Hexadecimal base
        /// </summary>
        /// <param name="Data2Encrypt"></param>
        /// <returns></returns>
        public static string EncryptToHexString(string Data2Encrypt)
        {
            var bytes = Encoding.ASCII.GetBytes(Data2Encrypt);
            var ushorts = (Encrypt(bytes)).ToUShortArray();
            var bigInt = Base65536Helper.FromArray(ushorts);

            return bigInt.ToHexadecimalString();
        }

        /// <summary>
        /// Decrypt an array of bytes (adapted from http://pages.infinit.net/ctech/20031101-0151.html)
        /// </summary>
        /// <param name="Buff"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] Buff)
        {
            // Create a 128 bits AES key
            SymmetricAlgorithm symAlgo = SymmetricAlgorithm.Create();

            var rsa = new RSACryptoServiceProvider();
            var RSAedkey = new byte[rsa.KeySize >> 3];
            Buffer.BlockCopy(Buff, 0, RSAedkey, 0, RSAedkey.Length);
            // Decrypt sym key using RSA
            var symKey = decryptRsa4SymKey(RSAedkey);

            var initVector = new byte[symAlgo.IV.Length];
            Buffer.BlockCopy(Buff, RSAedkey.Length, initVector, 0, initVector.Length);

            // Sym key decryption
            ICryptoTransform cryptoTran = symAlgo.CreateDecryptor(symKey, initVector);
            var startIdx = RSAedkey.Length + initVector.Length;
            var len = Buff.Length - startIdx;
            var decryptBytes = cryptoTran.TransformFinalBlock(Buff, startIdx, len);
            return decryptBytes;
        }

        /// <summary>
        /// Decrypt a Base64 string to the original string
        /// </summary>
        /// <param name="Base64String"></param>
        /// <returns></returns>
        public static string DecryptFromBase64String(string Base64String)
        {
            var data2Decrypt = Convert.FromBase64String(Base64String);
            return Encoding.ASCII.GetString(Decrypt(data2Decrypt));
        }

        /// <summary>
        /// Decrypt from hex string to the original string
        /// /// </summary>
        /// <param name="HexString"></param>
        /// <returns></returns>
        public static string DecryptFromHexString(string HexString)
        {
            var bigInt = BigIntegerExtensions.HexadecimalStringToDecimal(HexString);
            var ushorts = Base65536Helper.ToArray(bigInt);
            var bytes = ushorts.ToByteArray();
            var decBytes = Decrypt(bytes);

            return Encoding.ASCII.GetString(decBytes);
        }

    }
}
