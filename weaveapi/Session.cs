using Org.BouncyCastle.Utilities.Encoders;

namespace weaveapi;

public class Session
{
    private readonly string _organization;
    private readonly string _account;
    private readonly string publicKey;
    private readonly string scopes;
    private readonly string apiKey;

    private readonly byte[] secret;
    private readonly string secretExpireUTC;
    private readonly bool _integrityChecks;
    private int _nonce = 0;
    private readonly Dictionary<string, DataLayout> _tableLayoutCache = new();

    public Session(IReadOnlyDictionary<string, object> sessionResponse, string decryptedSecret)
    {
        _organization = sessionResponse["organization"].ToString();
        _account = sessionResponse["account"].ToString();
        publicKey = sessionResponse["publicKey"].ToString();
        scopes = sessionResponse["scopes"].ToString();
        apiKey = sessionResponse["apiKey"].ToString();

        secret = Base64.Decode(SignUtils.StringEncode(decryptedSecret));
        secretExpireUTC = sessionResponse["secretExpireUTC"].ToString();
        _integrityChecks = Boolean.Parse(sessionResponse["integrityChecks"].ToString());
    }

    public string IncrementNonceAndGetString()
    {
        _nonce++;
        return _nonce + "";
    }

    public string GetApiKey()
    {
        return apiKey;
    }

    public byte[] GetSecret()
    {
        return secret;
    }

    public string GetOrganization()
    {
        return _organization;
    }

    public string GetAccount()
    {
        return _account;
    }

    public bool IsIntegrityChecks()
    {
        return _integrityChecks;
    }

    public DataLayout GetDataLayout(string scope, string table)
    {
        return _tableLayoutCache[scope + ":" + table];
    }

    public bool HasLayoutForKey(string scope, string table)
    {
        return _tableLayoutCache.ContainsKey(scope + ":" + table);
    }

    public void CacheLayout(string scope, string table, DataLayout layout)
    {
        _tableLayoutCache[scope + ":" + table] = layout;
    }
}
