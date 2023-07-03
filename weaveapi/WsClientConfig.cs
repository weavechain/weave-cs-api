public class WsClientConfig
{
    private readonly bool _useWss;
    private readonly string _host;
    private readonly string _port;
    private readonly string _seedHex;
    private readonly string _clientPubKey;
    private readonly string _clientPrivKey;

    public WsClientConfig(
        string host,
        string port,
        string clientPubKey,
        string clientPrivKey,
        bool useWss,
        string seedHex
    )
    {
        _host = host;
        _port = port;
        _useWss = useWss;

        _seedHex = seedHex;

        _clientPubKey = clientPubKey;
        _clientPrivKey = clientPrivKey;
    }

    public bool isUseWss()
    {
        return _useWss;
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
