namespace weaveapi;

public class ReadOptions
{
    public const int DEFAULT_READ_TIMEOUT_SEC = 300;
    private readonly bool _verifyHash;
    private int _readTimeoutSec;

    public ReadOptions(
        bool verifyHash,
        int readTimeoutSec,
        int peersConsensus,
        bool enableMux,
        bool includeCached,
        string onBehalf,
        string signature,
        bool verifySourceSignature,
        bool getBatchHashes
    )
    {
        _verifyHash = verifyHash;
        _readTimeoutSec = readTimeoutSec;
        _peersConsensus = peersConsensus;
        _enableMux = enableMux;
        _includeCached = includeCached;
        _onBehalf = onBehalf;
        _signature = signature;
        _verifySourceSignature = verifySourceSignature;
        _getBatchHashes = getBatchHashes;
    }

    private int _peersConsensus;
    private bool _enableMux;
    private bool _includeCached;
    private string _onBehalf;
    private string _signature;
    private bool _verifySourceSignature;
    private bool _getBatchHashes;

    public static readonly ReadOptions Default =
        new(true, DEFAULT_READ_TIMEOUT_SEC, 0, false, false, null, null, false, false);
}
