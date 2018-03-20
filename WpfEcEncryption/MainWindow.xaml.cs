using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using EllipticCurves.ExtensionsAndHelpers;

namespace WpfEcEncryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public static MainWindow AppWindow;

        public MainWindow()
        {
            InitializeComponent();
            AppWindow = this;

            // generate keys xml file
            EncryptionHelper.AssignNewRsaKeyAndSaveXml();
        }

        private void btnEncrypt_Click(object sender, RoutedEventArgs e)
        {
            // check is null or empty
            var msg = Regex.Replace(txt2EncryptText.Text, @"\s+", "");
            if (string.IsNullOrEmpty(msg))
            {
                MessageBox.Show("Text to encrypt cannot be empty.", "WpfEcEncryption");
                return;
            }

            // Encryption
            var text2encrypt = txt2EncryptText.Text;
            var pbX = BigIntegerExtensions.HexadecimalStringToDecimal(txtPublicKeyX.Text);
            var pbY = BigIntegerExtensions.HexadecimalStringToDecimal(txtPublicKeyY.Text);
            var pb = new EcModPoint { x = pbX, y = pbY };
            var encryptStr = EcCryptographyHelper.EncryptSecP256k1Json(text2encrypt, pb);

            // First compression
            var compStr = CompressionHelper.ZipBase65536HexStringBase64(encryptStr);

            // Rsa encryption
            var rsaHex = EncryptionHelper.EncryptToHexString(compStr);

            // Second compression
            compStr = CompressionHelper.ZipBase65536HexStringBase64(rsaHex);

            txt2DecryptText.Text = compStr;
            txt2EncryptText.Text = string.Empty;
        }

        private void btnDecrypt_Click(object sender, RoutedEventArgs e)
        {
            // check is null or empty
            var msg = Regex.Replace(txt2DecryptText.Text, @"\s+", "");
            if (string.IsNullOrEmpty(msg))
            {
                MessageBox.Show("Text to decrypt cannot be empty.", "WpfEcEncryption");
                return;
            }

            // first decompression
            var decompMsg = CompressionHelper.UnzipBase65536HexStringBase64(txt2DecryptText.Text);

            // Rsa decryption
            var rsaDecBase64 = EncryptionHelper.DecryptFromHexString(decompMsg);

            // Second decompression
             decompMsg = CompressionHelper.UnzipBase65536HexStringBase64(rsaDecBase64);

            // Decryption
            var strSk = txtSecretKey.Text;
            var sk = BigIntegerExtensions.HexadecimalStringToDecimal(strSk);
            var decryptedStr = EcCryptographyHelper.DecryptSecP256k1Json(decompMsg, sk);

            txt2EncryptText.Text = decryptedStr;
            txt2DecryptText.Text = string.Empty;
        }

        private void btnGenEcKeys_Click(object sender, RoutedEventArgs e)
        {
            var eccWin = new EccGenKeyWindow();
            eccWin.WindowStartupLocation = WindowStartupLocation.CenterOwner;
            eccWin.ShowDialog();
        }
    }
}
