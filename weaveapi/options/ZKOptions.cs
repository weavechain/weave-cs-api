namespace weaveapi;

public class ZKOptions
{
    private static string WILDCARD = "*";

    public static List<string> ALL_ACTIVE_NODES = new List<string>() { WILDCARD };

    private bool _verifyHash;

    private int _readTimeoutSec;

    private List<string> _sources;

    private int _generators;

    private string _commitment; //32 bytes, base58 encoded

    private string _onBehalf;

    private string _signature;

    private bool _verifySourceSignature;

    public ZKOptions(
        bool verifyHash,
        int readTimeoutSec,
        List<string> sources,
        int generators,
        string commitment,
        string onBehalf,
        string signature,
        bool verifySourceSignature
    )
    {
        _verifyHash = verifyHash;
        _readTimeoutSec = readTimeoutSec;
        _sources = sources;
        _generators = generators;
        _commitment = commitment;
        _onBehalf = onBehalf;
        _signature = signature;
        _verifySourceSignature = verifySourceSignature;
    }
}
