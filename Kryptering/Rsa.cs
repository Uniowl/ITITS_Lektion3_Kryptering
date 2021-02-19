using System;
using System.Security.Cryptography;
using System.Text;

namespace Kryptering
{
    public class Rsa
    {
        public void Run(string data)
        {
            ComputeRsaCryptoServiceProvider(data);
        }
        
        static void ComputeRsaCryptoServiceProvider(string rawData)
        {
            try
            {
                UnicodeEncoding byteConverter = new UnicodeEncoding();

                byte[] dataToEncrypt = byteConverter.GetBytes(rawData);
                byte[] encryptedData;
                byte[] decryptedData;

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    encryptedData = RsaEncrypt(dataToEncrypt, rsa.ExportParameters(false), false);
                    
                    StringBuilder builder = new StringBuilder();
                
                    for (int i = 0; i < encryptedData.Length; i++)
                    {
                        builder.Append(encryptedData[i].ToString("x2"));
                    }

                    Console.WriteLine("Encrypted plaintext: {0}", builder);
                    
                    decryptedData = RsaDecrypt(encryptedData, rsa.ExportParameters(true), false);
                    
                    Console.WriteLine("Decrypted plaintext: {0}", byteConverter.GetString(decryptedData));
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("Encryption failed.");
            }
        }

        private static byte[] RsaEncrypt(byte[] dataToEncrypt, RSAParameters rsaKeyInfo, bool padding)
        {
            try
            {
                byte[] encryptedData;

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(rsaKeyInfo);
                    encryptedData = rsa.Encrypt(dataToEncrypt, padding);
                }

                return encryptedData;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }
        
        private static byte[] RsaDecrypt(byte[] dataToDecrypt, RSAParameters rsaKeyInfo, bool padding)
        {
            try
            {
                byte[] decryptedData;

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(rsaKeyInfo);
                    decryptedData = rsa.Decrypt(dataToDecrypt, padding);
                }

                return decryptedData;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                return null;
            }
        }
    }
}