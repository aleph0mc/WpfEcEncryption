using EllipticCurves.ExtensionsAndHelpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace WpfEcEncryption
{
    /// <summary>
    /// Interaction logic for EccGenKeyWindow.xaml
    /// </summary>
    public partial class EccGenKeyWindow : Window
    {
        public EccGenKeyWindow()
        {
            InitializeComponent();
        }

        private void txtChosenPwd_KeyDown(object sender, KeyEventArgs e)
        {
            var txtPwd = sender as TextBox;
            var pwd = txtPwd.Text;
            var strength = PasswordManager.Strength(pwd);
            pbStrength.Value = strength;
            txbStrength.Text = string.Concat(strength, " bits");
            lblCharLength.Content = string.Concat(pwd.Length, " chars");
            txbHash.Text = PasswordManager.Hash(pwd, SHA256.Create());
        }

        private void btnOk_Click(object sender, RoutedEventArgs e)
        {
            // encode the partioned str in Unicode
            var bytes = Encoding.ASCII.GetBytes(txtChosenPwd.Text);
            // convert to ushort array
            //var arrShort = encUtf8.ToUShortArray();
            // convert to bae 65536 big integer
            //var bi65536 = Base65536Helper.FromArray(arrShort);

            var bi = new BigInteger(bytes);
            var pk = EcCryptographyHelper.SecP256k1KeyPairGenerator(bi);

            //MainWindow.AppWindow.txtPublicKeyX.Text = pk.x.ToString();
            //MainWindow.AppWindow.txtPublicKeyY.Text = pk.y.ToString();
            // secret key
            MainWindow.AppWindow.txtSecretKey.Text = bi.ToHexadecimalString();

            // public key
            MainWindow.AppWindow.txtPublicKeyX.Text = pk.x.ToHexadecimalString();
            MainWindow.AppWindow.txtPublicKeyY.Text = pk.y.ToHexadecimalString();

            this.Close();
        }
    }
}
