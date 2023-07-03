namespace weaveapi;

public class HttpClientConfig
{
    private readonly bool _useHttps;
    private readonly string _host;
    private readonly string _port;
    private readonly string _seedHex;
    private readonly string _clientPubKey;
    private readonly string _clientPrivKey;

    public HttpClientConfig(
        string host,
        string port,
        string clientPubKey,
        string clientPrivKey,
        bool useHttps,
        string seedHex
    )
    {
        _host = host;
        _port = port;
        _useHttps = useHttps;

        _seedHex = seedHex;

        _clientPubKey = clientPubKey;
        _clientPrivKey = clientPrivKey;
    }

    public bool IsUseHttps()
    {
        return _useHttps;
    }

    public string GetHost()
    {
        return _host;
    }

    public string GetPort()
    {
        return _port;
    }

    public string GetClientPubKey()
    {
        return _clientPubKey;
    }

    public string GetClientPrivKey()
    {
        return _clientPrivKey;
    }

    public string GetSeedHex()
    {
        return _seedHex;
    }
}
