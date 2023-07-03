using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.Security;
using SimpleBase;

namespace weaveapi;

public static class SignUtils
{
    private static readonly JsonSerializerOptions SerializeOptions =
        new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };

    public static byte[] GetSharedSecret(byte[] privateKeyIn, byte[] publicKeyIn)
    {
        var agreement = new ECDHBasicAgreement();

        var curve = ECNamedCurveTable.GetByName("secP256k1");
        var ecParam = new ECDomainParameters(
            curve.Curve,
            curve.G,
            curve.N,
            curve.H,
            curve.GetSeed()
        );
        var privKey = new ECPrivateKeyParameters(new BigInteger(1, privateKeyIn), ecParam);
        var point = ecParam.Curve.DecodePoint(publicKeyIn);
        var pubKey = new ECPublicKeyParameters(point, ecParam);

        agreement.Init(privKey);
        var secret = agreement.CalculateAgreement(pubKey);
        return secret.ToByteArrayUnsigned();
    }

    public static string GenerateSharedKeySignature(
        string toSign,
        byte[]? sharedSecret,
        byte[] iv,
        string seedHex
    )
    {
        var signature = Encrypt(toSign, sharedSecret, iv, seedHex);
        return ToHexString(signature);
    }

    private static byte[] Encrypt(string plainText, byte[] key, byte[] iv, string seedHex)
    {
        iv = XorIvWithApiSeed(iv, seedHex);
        using var aes = new AesManaged();

        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        var encryptor = aes.CreateEncryptor(key, iv);
        using var ms = new MemoryStream();
        using var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write);
        using (var sw = new StreamWriter(cs))
            sw.Write(plainText);
        var encrypted = ms.ToArray();
        return encrypted;
    }

    public static string Decrypt(byte[] cipherText, byte[] key, byte[] iv, string seedHex)
    {
        iv = XorIvWithApiSeed(iv, seedHex);
        using var aes = new AesManaged();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        var decryptor = aes.CreateDecryptor(key, iv);
        using var ms = new MemoryStream(cipherText);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var reader = new StreamReader(cs);
        return reader.ReadToEnd();
    }

    private static byte[] XorIvWithApiSeed(IReadOnlyList<byte> iv, string seedHex)
    {
        var seed = HexStringToByteArray(seedHex);
        var s = new byte[iv.Count];
        for (var i = 0; i < iv.Count; i++)
        {
            s[i] = iv[i];
            s[i] ^= seed[i % seed.Length];
        }
        return s;
    }

    public static byte[] HexStringToByteArray(string hexString)
    {
        var resultLength = hexString.Length / 2;
        var result = new byte[resultLength];
        for (var i = 0; i < resultLength; i++)
        {
            result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
        }

        return result;
    }

    public static byte[] HashHmac(byte[] secret, string message)
    {
        var hash = new HMACSHA256(secret);
        return hash.ComputeHash(StringEncode(message));
    }

    public static byte[] StringEncode(string text)
    {
        var encoding = new ASCIIEncoding();
        return encoding.GetBytes(text);
    }

    public static string ToHexString(byte[] ba)
    {
        return BitConverter.ToString(ba).Replace("-", "");
    }

    public static List<Records.IntegrityWrapper> GetIntegrity(
        Records records,
        DataLayout dataLayout,
        string seedHex,
        string publicKey,
        Ed25519PrivateKeyParameters decodedClientPrivKey
    )
    {
        var items = records.Items;

        var idBuffer = "";
        var hashBuffer = "";
        var first = true;
        foreach (var record in items)
        {
            if (first)
            {
                first = false;
            }
            else
            {
                idBuffer += " ";
                hashBuffer += "\n";
            }
            StandardizeRecord(record, dataLayout);

            var data = JsonSerializer.Serialize(record);
            var hash = Convert.ToBase64String(HashHmac(StringEncode(seedHex), data));

            idBuffer += record[0];
            hashBuffer += hash;
        }
        var toSignHashOfHashes = idBuffer + "\n" + hashBuffer;
        var hashOfHashes = Convert.ToBase64String(
            HashHmac(StringEncode(seedHex), toSignHashOfHashes)
        );
        var signature = new SortedDictionary<string, string>
        {
            ["recordsHash"] = hashOfHashes,
            ["pubKey"] = publicKey
        };

        var signatureString = SignEd25519(
            JsonSerializer.Serialize(signature, SerializeOptions),
            decodedClientPrivKey
        );
        signature["sig"] = signatureString;

        return new List<Records.IntegrityWrapper>
        {
            new("0", new Dictionary<string, string>(signature))
        };
    }

    public static string[] GenerateKeys()
    {
        ECKeyPairGenerator gen = new ECKeyPairGenerator("ECDH");
        X9ECParameters ecp = SecNamedCurves.GetByName("secp256k1");
        ECDomainParameters ecSpec = new ECDomainParameters(
            ecp.Curve,
            ecp.G,
            ecp.N,
            ecp.H,
            ecp.GetSeed()
        );

        ECKeyGenerationParameters ecgp = new ECKeyGenerationParameters(ecSpec, new SecureRandom());
        gen.Init(ecgp);
        AsymmetricCipherKeyPair eckp = gen.GenerateKeyPair();

        ECPublicKeyParameters ecPub = (ECPublicKeyParameters)eckp.Public;
        byte[] XCoordBytes = ecPub.Q.XCoord.GetEncoded();
        byte[] signBasedPadding = new byte[XCoordBytes.Length + 1];
        signBasedPadding[0] = ecPub.Q.YCoord.ToBigInteger().SignValue > 0 ? (byte)3 : (byte)2;
        Array.Copy(XCoordBytes, 0, signBasedPadding, 1, XCoordBytes.Length);
        var pub = "weave" + new Base58(Base58Alphabet.Bitcoin).Encode(signBasedPadding);

        ECPrivateKeyParameters ecPri = (ECPrivateKeyParameters)eckp.Private;
        byte[] bytes = ecPri.D.ToByteArray();
        byte[] len32 = new byte[32];
        if (bytes.Length == 33)
        {
            Array.Copy(bytes, 1, len32, 0, 32);
        }
        else
        {
            len32 = bytes;
        }
        var pvk = new Base58(Base58Alphabet.Bitcoin).Encode(len32);
        return new string[] { pub, pvk };
    }

    public static string SignEd25519(
        string toSign,
        Ed25519PrivateKeyParameters decodedClientPrivKey
    )
    {
        var sig = new byte[Ed25519PrivateKeyParameters.SignatureSize];
        var toSignBytes = StringEncode(toSign);
        decodedClientPrivKey.Sign(
            Ed25519.Algorithm.Ed25519,
            null,
            toSignBytes,
            0,
            toSignBytes.Length,
            sig,
            0
        );

        return new Base58(Base58Alphabet.Bitcoin).Encode(sig);
    }

    public static byte[] GeneratePrivateEdSecretBytesFromDecodedClientPrivKey(byte[] decodedPrivKey)
    {
        var seed = ByteArrayToLong(decodedPrivKey, 6);
        var random = new JavaRandom(seed);
        var bytes = new byte[32];
        for (var i = 0; i < bytes.Length / 4; i++)
        {
            var nextInt = random.Next(32);
            var nextIntBytes = BitConverter.GetBytes(nextInt);
            bytes[i * 4] = nextIntBytes[0];
            bytes[i * 4 + 1] = nextIntBytes[1];
            bytes[i * 4 + 2] = nextIntBytes[2];
            bytes[i * 4 + 3] = nextIntBytes[3];
        }
        for (var i = 0; i < 32; i++)
        {
            bytes[i] ^= decodedPrivKey[i];
        }

        return bytes;
    }

    private static ulong ByteArrayToLong(byte[] bytes, int size)
    {
        ulong res = 0;
        for (int i = 0; i < size; i++)
        {
            res = res * 256 + bytes[i];
        }
        return res;
    }

    private static void StandardizeRecord(IList<object> record, DataLayout dataLayout)
    {
        for (var i = 0; i < dataLayout.GetTypes().Count; i++)
        {
            if (i < record.Count)
            {
                record[i] = ConvertRecordFields(record[i], dataLayout.GetTypes()[i]);
            }
            else
            {
                record[i] = null;
            }
        }
    }

    private static object ConvertRecordFields(object recordField, object type)
    {
        var typeString = type.ToString();
        if (typeString.Equals("LONG") || typeString.Equals("TIMESTAMP"))
        {
            return long.Parse(recordField.ToString());
        }

        if (typeString.Equals("STRING"))
        {
            return recordField.ToString();
        }

        return recordField.ToString();
    }

    public static byte[] GenerateIv()
    {
        var random = new SecureRandom();
        var iv = random.GenerateSeed(16);
        return iv;
    }
}
