using System;
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
        
        static void Main()
        {
            TestSignature();
            TestSignatureCorruption();
            TestMessageCorruption();
            TestPrivateKeyRecovery();
        }
    }
}
