using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace CryptographyApp
{
    internal class Program
    {
        private static RsaKeyPair _currentRsaKeys;

        static void Main(string[] args)
        {
            while (true)
            {
                Console.Clear();
                Console.WriteLine("==========================================");
                Console.WriteLine("      PROFESSIONAL CRYPTOGRAPHY TOOL      ");
                Console.WriteLine("==========================================");
                Console.WriteLine("1. Symmetric Encryption (AES)");
                Console.WriteLine("2. Asymmetric Encryption (RSA)");
                Console.WriteLine("3. Hashing Algorithms");
                Console.WriteLine("4. Exit");
                Console.Write("\nSelect an option: ");

                string choice = Console.ReadLine();

                switch (choice)
                {
                    case "1":
                        SymmetricMenu();
                        break;
                    case "2":
                        AsymmetricMenu();
                        break;
                    case "3":
                        HashingMenu();
                        break;
                    case "4":
                        return;
                    default:
                        Console.WriteLine("Invalid selection.");
                        break;
                }
            }
        }

        static void SymmetricMenu()
        {
            Console.Clear();
            Console.WriteLine("--- AES OPERATIONS ---");
            Console.WriteLine("1. Encrypt Text");
            Console.WriteLine("2. Decrypt Text");
            Console.WriteLine("3. Back to Main Menu");
            Console.Write("\nSelect: ");

            string choice = Console.ReadLine();
            if (choice == "3") return;

            Console.Write("Enter Password: ");
            string password = Console.ReadLine();

            try
            {
                if (choice == "1")
                {
                    Console.Write("Enter Text to Encrypt: ");
                    string text = Console.ReadLine();
                    string encrypted = AesProvider.Encrypt(text, password);
                    Console.WriteLine($"\nResult (Base64): {encrypted}");
                }
                else if (choice == "2")
                {
                    Console.Write("Enter Base64 CipherText: ");
                    string text = Console.ReadLine();
                    string decrypted = AesProvider.Decrypt(text, password);
                    Console.WriteLine($"\nResult (Plain): {decrypted}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }

        static void AsymmetricMenu()
        {
            Console.Clear();
            Console.WriteLine("--- RSA OPERATIONS ---");
            Console.WriteLine("1. Generate New Key Pair");
            Console.WriteLine("2. Encrypt Text (Requires Public Key)");
            Console.WriteLine("3. Decrypt Text (Requires Private Key)");
            Console.WriteLine("4. Back to Main Menu");
            Console.Write("\nSelect: ");

            string choice = Console.ReadLine();
            if (choice == "4") return;

            try
            {
                if (choice == "1")
                {
                    _currentRsaKeys = RsaProvider.GenerateKeys();
                    Console.WriteLine("\nKeys Generated Successfully.");
                    Console.WriteLine("Public Key stored in memory.");
                    Console.WriteLine("Private Key stored in memory.");
                    Console.WriteLine($"\nPublic Key Preview: {_currentRsaKeys.PublicKey.Substring(0, 50)}...");
                }
                else if (choice == "2")
                {
                    if (string.IsNullOrEmpty(_currentRsaKeys.PublicKey))
                    {
                        Console.WriteLine("Error: No keys generated yet. Please generate keys first.");
                    }
                    else
                    {
                        Console.Write("Enter Text to Encrypt: ");
                        string text = Console.ReadLine();
                        string encrypted = RsaProvider.Encrypt(text, _currentRsaKeys.PublicKey);
                        Console.WriteLine($"\nEncrypted Result: {encrypted}");
                    }
                }
                else if (choice == "3")
                {
                    if (string.IsNullOrEmpty(_currentRsaKeys.PrivateKey))
                    {
                        Console.WriteLine("Error: No keys generated yet.");
                    }
                    else
                    {
                        Console.Write("Enter Encrypted Text: ");
                        string text = Console.ReadLine();
                        string decrypted = RsaProvider.Decrypt(text, _currentRsaKeys.PrivateKey);
                        Console.WriteLine($"\nDecrypted Result: {decrypted}");
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }

        static void HashingMenu()
        {
            Console.Clear();
            Console.WriteLine("--- HASHING ALGORITHMS ---");
            Console.WriteLine("1. MD5");
            Console.WriteLine("2. SHA-1");
            Console.WriteLine("3. SHA-256");
            Console.WriteLine("4. SHA-384");
            Console.WriteLine("5. SHA-512");
            Console.WriteLine("6. Compute All");
            Console.WriteLine("7. Back to Main Menu");
            Console.Write("\nSelect Algorithm: ");

            string choice = Console.ReadLine();
            if (choice == "7") return;

            Console.Write("Enter Text to Hash: ");
            string input = Console.ReadLine();
            Console.WriteLine();

            if (choice == "1") Console.WriteLine($"MD5:    {HashProvider.Compute(input, "MD5")}");
            else if (choice == "2") Console.WriteLine($"SHA1:   {HashProvider.Compute(input, "SHA1")}");
            else if (choice == "3") Console.WriteLine($"SHA256: {HashProvider.Compute(input, "SHA256")}");
            else if (choice == "4") Console.WriteLine($"SHA384: {HashProvider.Compute(input, "SHA384")}");
            else if (choice == "5") Console.WriteLine($"SHA512: {HashProvider.Compute(input, "SHA512")}");
            else if (choice == "6")
            {
                Console.WriteLine($"MD5:    {HashProvider.Compute(input, "MD5")}");
                Console.WriteLine($"SHA1:   {HashProvider.Compute(input, "SHA1")}");
                Console.WriteLine($"SHA256: {HashProvider.Compute(input, "SHA256")}");
                Console.WriteLine($"SHA384: {HashProvider.Compute(input, "SHA384")}");
                Console.WriteLine($"SHA512: {HashProvider.Compute(input, "SHA512")}");
            }
            else
            {
                Console.WriteLine("Invalid selection.");
            }

            Console.WriteLine("\nPress any key to continue...");
            Console.ReadKey();
        }
    }

    public static class AesProvider
    {
        public static string Encrypt(string plainText, string password)
        {
            byte[] key = DeriveKey(password);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.GenerateIV();

                using (MemoryStream ms = new MemoryStream())
                {
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                        cs.Write(plainBytes, 0, plainBytes.Length);
                    }
                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        public static string Decrypt(string cipherText, string password)
        {
            byte[] fullCipher = Convert.FromBase64String(cipherText);
            byte[] key = DeriveKey(password);

            using (Aes aes = Aes.Create())
            {
                byte[] iv = new byte[16];
                Array.Copy(fullCipher, 0, iv, 0, iv.Length);

                aes.Key = key;
                aes.IV = iv;

                using (MemoryStream ms = new MemoryStream(fullCipher, 16, fullCipher.Length - 16))
                using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        private static byte[] DeriveKey(string password)
        {
            using (SHA256 sha = SHA256.Create())
            {
                return sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }
    }

    public struct RsaKeyPair
    {
        public string PublicKey;
        public string PrivateKey;
    }

    public static class RsaProvider
    {
        public static RsaKeyPair GenerateKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                return new RsaKeyPair
                {
                    PublicKey = rsa.ToXmlString(false),
                    PrivateKey = rsa.ToXmlString(true)
                };
            }
        }

        public static string Encrypt(string plainText, string publicKeyXml)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(publicKeyXml);
                byte[] data = Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = rsa.Encrypt(data, false);
                return Convert.ToBase64String(encrypted);
            }
        }

        public static string Decrypt(string cipherText, string privateKeyXml)
        {
            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(privateKeyXml);
                byte[] data = Convert.FromBase64String(cipherText);
                byte[] decrypted = rsa.Decrypt(data, false);
                return Encoding.UTF8.GetString(decrypted);
            }
        }
    }

    public static class HashProvider
    {
        public static string Compute(string input, string algorithmName)
        {
            using (HashAlgorithm algorithm = GetAlgorithm(algorithmName))
            {
                if (algorithm == null) return "Invalid Algorithm";
                byte[] bytes = algorithm.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
        }

        private static HashAlgorithm GetAlgorithm(string name)
        {
            switch (name.ToUpper())
            {
                case "MD5": return MD5.Create();
                case "SHA1": return SHA1.Create();
                case "SHA256": return SHA256.Create();
                case "SHA384": return SHA384.Create();
                case "SHA512": return SHA512.Create();
                default: return null;
            }
        }
    }
}