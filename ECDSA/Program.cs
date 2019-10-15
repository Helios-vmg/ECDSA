using System;
using System.Diagnostics;
using System.Globalization;
using System.Net.Configuration;
using System.Numerics;
using System.Text;

namespace ECDSA
{
    class Program
    {
        //Signs a message and verifies the signature.
        static void TestSignature()
        {
            var message = Encoding.UTF8.GetBytes("Hello, World!\n");
            BigInteger privateKey = 7;
            var publicKey = Secp256k1.Param_G * privateKey;
            var signature = Secp256k1.SignMessage(message, privateKey);
            var valid = Secp256k1.VerifySignature(message, signature, publicKey);
            Console.WriteLine(valid);
            Console.WriteLine(new string('-', 50));
        }

        //Signs a message, corrupts the signature and shows how the verification fails.
        static void TestSignatureCorruption()
        {
            var message = Encoding.UTF8.GetBytes("Hello, World!\n");
            BigInteger privateKey = 7;
            var publicKey = Secp256k1.Param_G * privateKey;
            var signature = Secp256k1.SignMessage(message, privateKey);
            var valid1 = Secp256k1.VerifySignature(message, signature, publicKey);
            signature.S++;
            var valid2 = Secp256k1.VerifySignature(message, signature, publicKey);
            Console.WriteLine(valid1);
            Console.WriteLine(valid2);
            Console.WriteLine(new string('-', 50));
        }

        //Signs a message, corrupts it after signing it, and shows how the verification fails.
        static void TestMessageCorruption()
        {
            var message = Encoding.UTF8.GetBytes("Hello, World!\n");
            BigInteger privateKey = 7;
            var publicKey = Secp256k1.Param_G * privateKey;
            var signature = Secp256k1.SignMessage(message, privateKey);
            var valid1 = Secp256k1.VerifySignature(message, signature, publicKey);
            message = Encoding.UTF8.GetBytes("Hello, World?\n");
            var valid2 = Secp256k1.VerifySignature(message, signature, publicKey);
            Console.WriteLine(valid1);
            Console.WriteLine(valid2);
            Console.WriteLine(new string('-', 50));
        }

        private class BadSig
        {
            public byte[] Msg;
            public Secp256k1.Sig Sig;

            public BadSig(byte[] msg, Secp256k1.Sig sig)
            {
                Msg = msg;
                Sig = sig;
            }
        }

        static BadSig GenerateBadSignature1(BigInteger pk, BigInteger nonce)
        {
            var message = Encoding.UTF8.GetBytes("Hello, World from 1!\n");
            var sig = Secp256k1.SignMessage(message, pk, nonce);
            return new BadSig(message, sig);
        }

        static BadSig GenerateBadSignature2(BigInteger pk, BigInteger nonce)
        {
            var message = Encoding.UTF8.GetBytes("Hello, World from 2!\n");
            var sig = Secp256k1.SignMessage(message, pk, nonce);
            return new BadSig(message, sig);
        }

        private static BigInteger _pk = 0;
        private static BigInteger _nonce = 0;

        //Generates two signatures for two different messages using the same nonce twice.
        static Tuple<BadSig, BadSig> GenerateBadSignatures()
        {
            var pk = Secp256k1.GeneratePrivateKey();
            _pk = pk;
            Console.WriteLine($"Private key:           {pk.ToString("X")}");
            var nonce = Secp256k1.GenerateRandomNonce();
            _nonce = nonce;
            var sig1 = GenerateBadSignature1(pk, nonce);
            var sig2 = GenerateBadSignature2(pk, nonce);
            return new Tuple<BadSig, BadSig>(sig1, sig2);
        }

        //Shows recovery of the private key from two signatures with repeated nonces.
        static void TestPrivateKeyRecovery()
        {
            var sigs = GenerateBadSignatures();
            Console.WriteLine("I no longer have the private key.");
            var pk = Secp256k1.RecoverPrivateKey(sigs.Item1.Msg, sigs.Item1.Sig, sigs.Item2.Msg, sigs.Item2.Sig);
            Console.WriteLine($"Recovered private key: {pk.ToString("X")}");
        }

        static void TestSecp256k1(string digestString, string privateKeyString, string nonceString, string rString, string sString)
        {
            var digest = BigInteger.Parse("0" + digestString, NumberStyles.HexNumber);
            var privateKey = BigInteger.Parse("0" + privateKeyString, NumberStyles.HexNumber);
            var nonce = BigInteger.Parse("0" + nonceString, NumberStyles.HexNumber);
            var r = BigInteger.Parse("0" + rString, NumberStyles.HexNumber);
            var s = BigInteger.Parse("0" + sString, NumberStyles.HexNumber);
            var publicKey = Secp256k1.Param_G * privateKey;

            var sw = new Stopwatch();

            sw.Start();
            var signature = Secp256k1.SignDigest(digest, privateKey, nonce);
            if (signature == null || signature.R != r || signature.S != s)
                throw new Exception("Secp256k1 fails signing test");
            sw.Stop();
            var t0 = sw.ElapsedMilliseconds;

            sw.Restart();
            if (!Secp256k1.VerifySignature(digest, signature, publicKey))
                throw new Exception("Secp256k1 fails signature verification test");
            sw.Stop();
            var t1 = sw.ElapsedMilliseconds;

            Console.WriteLine($"Signing time:      {t0} ms");
            Console.WriteLine($"Verification time: {t1} ms");
        }

        static void TestSecp256k1()
        {
            TestSecp256k1("4b688df40bcedbe641ddb16ff0a1842d9c67ea1c3bf63f3e0471baa664531d1a", "ebb2c082fd7727890a28ac82f6bdf97bad8de9f5d7c9028692de1a255cad3e0f", "49a0d7b786ec9cde0d0721d72804befd06571c974b191efb42ecf322ba9ddd9a", "241097efbf8b63bf145c8961dbdf10c310efbb3b2676bbc0f8b08505c9e2f795", "021006b7838609339e8b415a7f9acb1b661828131aef1ecbc7955dfb01f3ca0e");
        }

        static void Main()
        {
            TestSecp256k1();
            TestSignature();
            TestSignatureCorruption();
            TestMessageCorruption();
            TestPrivateKeyRecovery();
        }
    }
}
