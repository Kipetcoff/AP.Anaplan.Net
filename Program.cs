using System;
using System.Configuration;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace AP.Anaplan.Net
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Let's begin. Enter any key");
            Console.ReadLine();

            //Get random string
            var random = RandomString(100);

            //Encode in base-64
            string encodedData = GetEncodedData(random);

            //Sign by key and encode in base-64
            string encodedSignedData = GetEncodedSignedData(random);

            Console.WriteLine($"Encoded Data:{encodedData}");
            Console.WriteLine();
            Console.WriteLine($"Signed Encoded Data:{encodedSignedData}");

            Console.ReadLine();
        }


        private static string RandomString(int length)
        {
            var random = new Random();
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
              .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        private static string GetEncodedData(string random)
        {
            var byteConverter = new ASCIIEncoding();

            return Convert.ToBase64String(byteConverter.GetBytes(random));
        }

        private static string GetEncodedSignedData(string random)
        {
            var byteConverter = new ASCIIEncoding();
            var originalData = byteConverter.GetBytes(random);
            var rsaAlg = GetRsaProvider();
            var signedData = rsaAlg.SignData(originalData, SHA512.Create());
            return Convert.ToBase64String(signedData);

        }

        private static RSACryptoServiceProvider GetRsaProvider()
        {
            RsaPrivateCrtKeyParameters pars;
            using (var reader = System.IO.File.OpenText(ConfigurationManager.AppSettings.Get("PrivateKeyPath")))
                pars = (RsaPrivateCrtKeyParameters)new PemReader(reader).ReadObject();

            return (RSACryptoServiceProvider)DotNetUtilities.ToRSA(pars);
        }
    }
}
