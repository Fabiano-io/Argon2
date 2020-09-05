using Konscious.Security.Cryptography;
using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Argon2.App
{
    class Program
    {
        static void Main(string[] args)
        {
            var password = "Hello World!";
            var stopwatch = Stopwatch.StartNew();

            Console.WriteLine($"Creating hash for password '{ password }'.");

            var salt = CreateSalt();
            Console.WriteLine($"Using salt '{ Convert.ToBase64String(salt) }'.");

            var hash = HashPassword(password, salt);
            Console.WriteLine($"Hash is '{ Convert.ToBase64String(hash) }'.");

            var saltText = Convert.ToBase64String(salt);
            byte[] saltByte = Convert.FromBase64String(saltText);
            var hashText = Convert.ToBase64String(hash);
            byte[] hashByte = Convert.FromBase64String(hashText);

            stopwatch.Stop();
            Console.WriteLine($"Process took { stopwatch.ElapsedMilliseconds / 1024.0 } s");

            stopwatch = Stopwatch.StartNew();
            Console.WriteLine($"Verifying hash...");

            var success = VerifyHash(password, salt, hash);
            Console.WriteLine(success ? "Success!" : "Failure!");

            stopwatch.Stop();
            Console.WriteLine($"Process took { stopwatch.ElapsedMilliseconds / 1024.0 } s");
        }

        private static byte[] CreateSalt()
        {
            var buffer = new byte[16];
            var rng = new RNGCryptoServiceProvider();
            rng.GetBytes(buffer);
            return buffer;
        }

        private static byte[] HashPassword(string password, byte[] salt)
        {
            var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password));

            argon2.Salt = salt;
            argon2.DegreeOfParallelism = 8; // four cores
            argon2.Iterations = 4;
            argon2.MemorySize = 1024 * 1024; // 1 GB

            return argon2.GetBytes(16);            
        }

        private static bool VerifyHash(string password, byte[] salt, byte[] hash)
        {
            var newHash = HashPassword(password, salt);
            return hash.SequenceEqual(newHash);
        }
    }
}
