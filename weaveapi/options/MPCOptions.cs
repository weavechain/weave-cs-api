namespace weaveapi;

public class MPCOptions
{
    private static string WILDCARD = "*";

    private bool _verifyHash;

    private int _readTimeoutSec;

    private List<string> _sources;

    private string _transform;

    private string _onBehalf;

    private string _signature;

    private bool _verifySourceSignature;

    public MPCOptions(
        bool verifyHash,
        int readTimeoutSec,
        List<string> sources,
        string transform,
        string onBehalf,
        string signature,
        bool verifySourceSignature
    )
    {
        _verifyHash = verifyHash;
        _readTimeoutSec = readTimeoutSec;
        _sources = sources;
        _transform = transform;
        _onBehalf = onBehalf;
        _signature = signature;
        _verifySourceSignature = verifySourceSignature;
    }
}
