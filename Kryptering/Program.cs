using System;
using System.Security.Cryptography;
using System.Text;

namespace Kryptering
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.Write("Please enter message to encrypt and hash: ");
            string plainData = Console.ReadLine();
            string plainData2 = "Boobss";
         
            Console.WriteLine($"Plain data: {plainData}");
            Console.WriteLine($"Plain data 2: {plainData2}");
            
            var sha = new Sha256();
            var response = sha.Run(plainData);

            Console.WriteLine("Sha256:");
            Console.WriteLine(response);
            Console.WriteLine("\n");
            
            Console.WriteLine("RSA:");
            var rsa = new Rsa();
            rsa.Run(plainData);
            Console.WriteLine("\n");
            
            Console.WriteLine("AesManaged:");
            var aesM = new AesM();
            aesM.Run(plainData);
        }
    }
}