using SimpleBase;
using Base58 = SimpleBase.Base58;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;

namespace weaveapi;

public class ApiContext
{
    private const string EncodedKeyPrefix = "weave";

    private readonly string _clientPubKey;
    private readonly string _clientPrivKey;

    private readonly byte[] _decodedClientPubKey;
    private readonly byte[] _decodedClientPrivKey;

    private Ed25519PrivateKeyParameters _edClientPrivateKey;
    private Ed25519PublicKeyParameters _edClientPublicKey;

    private readonly string _seedHex;

    private byte[]? _decodedServerPubKey;

    private byte[]? _sharedSecret;

    public ApiContext(HttpClientConfig config)
    {
        _clientPubKey = config.GetClientPubKey();
        _decodedClientPubKey = _clientPubKey.StartsWith(EncodedKeyPrefix)
            ? new Base58(Base58Alphabet.Bitcoin).Decode(
                _clientPubKey.AsSpan(EncodedKeyPrefix.Length)
            )
            : new Base58(Base58Alphabet.Bitcoin).Decode(_clientPubKey);

        _clientPrivKey = config.GetClientPrivKey();
        _decodedClientPrivKey = new Base58(Base58Alphabet.Bitcoin).Decode(_clientPrivKey);

        SetEdClientKeys();

        _seedHex = config.GetSeedHex();
    }

    public ApiContext(WsClientConfig config)
    {
        _clientPubKey = config.GetClientPubKey();
        _decodedClientPubKey = _clientPubKey.StartsWith(EncodedKeyPrefix)
            ? new Base58(Base58Alphabet.Bitcoin).Decode(
                _clientPubKey.AsSpan(EncodedKeyPrefix.Length)
            )
            : new Base58(Base58Alphabet.Bitcoin).Decode(_clientPubKey);

        _clientPrivKey = config.GetClientPrivKey();
        _decodedClientPrivKey = new Base58(Base58Alphabet.Bitcoin).Decode(_clientPrivKey);

        SetEdClientKeys();

        _seedHex = config.GetSeedHex();
    }

    private void SetEdClientKeys()
    {
        var privateSecretBytes = SignUtils.GeneratePrivateEdSecretBytesFromDecodedClientPrivKey(
            _decodedClientPrivKey
        );
        _edClientPrivateKey = new Ed25519PrivateKeyParameters(privateSecretBytes, 0);
        _edClientPublicKey = _edClientPrivateKey.GeneratePublicKey();
    }

    public void SetDecodedServerPubKey(string encodedServerPubKey)
    {
        var encodedServerPublicKey = JsonSerializer.Deserialize<Dictionary<string, string>>(
            encodedServerPubKey
        )["data"];
        var decodedServerPubKey = encodedServerPublicKey.StartsWith(EncodedKeyPrefix)
            ? new Base58(Base58Alphabet.Bitcoin).Decode(
                encodedServerPublicKey.AsSpan(EncodedKeyPrefix.Length)
            )
            : new Base58(Base58Alphabet.Bitcoin).Decode(encodedServerPublicKey);
        _decodedServerPubKey = decodedServerPubKey;
    }

    public void ComputeSharedSecret()
    {
        _sharedSecret = SignUtils.GetSharedSecret(_decodedClientPrivKey, _decodedServerPubKey);
    }

    public string GetEncodedClientPubKey()
    {
        return _clientPubKey;
    }

    public string GetEncodedClientPrivKey()
    {
        return _clientPrivKey;
    }

    public byte[] GetDecodedClientPubKey()
    {
        return _decodedClientPubKey;
    }

    public byte[] GetDecodedClientPrivKey()
    {
        return _decodedClientPrivKey;
    }

    public byte[]? GetDecodedServerPubKey()
    {
        return _decodedServerPubKey;
    }

    public byte[]? GetSharedSecret()
    {
        return _sharedSecret;
    }

    public string GetSeedHex()
    {
        return _seedHex;
    }

    public Ed25519PrivateKeyParameters GetEdClientPrivateKey()
    {
        return _edClientPrivateKey;
    }

    public Ed25519PublicKeyParameters GetEdClientPublicKey()
    {
        return _edClientPublicKey;
    }
}
