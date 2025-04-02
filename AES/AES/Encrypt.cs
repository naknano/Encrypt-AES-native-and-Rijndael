using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Security.Cryptography;
using System.Text;

namespace AES.AES
{
    public class Encrypt
    {

        private byte[] cryptkey = Encoding.ASCII.GetBytes("1234567891234567");
        private byte[] initVector = Encoding.ASCII.GetBytes("1234567891234567");

        public string EncryptAESOld(string stringData, string stringPassword, string stringIV, string stringSalt)
        {
            try
            {
                byte[] dataByes = Convert.FromBase64String(stringData);
                byte[] passwordBytes = Convert.FromBase64String(stringPassword);
                byte[] ivBytes = Convert.FromBase64String(stringIV);
                byte[] saltBytes = Convert.FromBase64String(stringSalt);
                string stringEncrypt = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    using (RijndaelManaged AES = new RijndaelManaged())
                    {
                       
                        AES.BlockSize = 128;


                        AES.KeySize = 256;
                        var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 100);
                        AES.Key = key.GetBytes(AES.KeySize / 8);
                        AES.IV = ivBytes;
                        AES.Mode = CipherMode.CBC;




                        using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                        {
                            cs.Write(dataByes, 0, dataByes.Length);
                            cs.Close();
                        }
                        stringEncrypt = Convert.ToBase64String(ms.ToArray());
                    }
                }
                return stringEncrypt;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        public string EncryptAES(string textToCrypt)
        {
            try
            {
                using (var rijndaelManaged =
                       new RijndaelManaged
                                { Key = cryptkey, IV = initVector, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = 256 }
                )

                using (var memoryStream = new MemoryStream())
                using (var cryptoStream =
                       new CryptoStream(memoryStream,
                           rijndaelManaged.CreateEncryptor(cryptkey, initVector),
                           CryptoStreamMode.Write))
                {
                    using (var ws = new StreamWriter(cryptoStream))
                    {
                        ws.Write(textToCrypt);
                    }
                    return Convert.ToBase64String(memoryStream.ToArray());
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
        }

        public string EncryptAESNative(string plainText)
        {
            using var aes = Aes.Create();
            aes.Key = Encoding.UTF8.GetBytes("1234567891234567");
            aes.IV = Encoding.UTF8.GetBytes("1234567891234567");

            var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

            using var memoryStream = new MemoryStream();
            using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
            {
                using (var streamWriter = new StreamWriter(cryptoStream))
                {
                    streamWriter.Write(plainText);
                }
            }

            return Convert.ToBase64String(memoryStream.ToArray());
        }



        public string DecryptAES(string cipherData)
        {
            try
            {
                using (var rijndaelManaged =
                       new RijndaelManaged { Key = cryptkey, IV = initVector, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7, KeySize = 256 })
                using (var memoryStream =
                       new MemoryStream(Convert.FromBase64String(cipherData)))
                using (var cryptoStream =
                       new CryptoStream(memoryStream,
                           rijndaelManaged.CreateDecryptor(cryptkey, initVector),
                           CryptoStreamMode.Read))
                {
                    return new StreamReader(cryptoStream).ReadToEnd();
                }
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("A Cryptographic error occurred: {0}", e.Message);
                return null;
            }
        }
    }
}
