namespace weaveapi;

public class WriteOptions
{
    private const bool DefaultGuaranteedDelivery = true;
    private const int DefaultMinAcks = 1;
    private const bool DefaultMemoryAcks = false;
    private const int DefaultHashAcks = 1;
    private const int DefaultWriteTimeoutSec = 300;

    private bool _guaranteed;
    private int _minAcks;
    private bool _inMemoryAcks;
    private int _minHashAcks;
    private int _writeTimeoutSec;
    private bool _allowDistribute;
    private bool _signOnChain;
    private bool _syncSigning;
    private bool _allowRemoteBatching;
    private bool _allowLocalBatching;
    private BatchingOptions _batchingOptions;

    public WriteOptions(
        bool guaranteed,
        int minAcks,
        bool inMemoryAcks,
        int minHashAcks,
        int writeTimeoutSec,
        bool allowDistribute,
        bool signOnChain,
        bool syncSigning,
        bool allowRemoteBatching,
        bool allowLocalBatching,
        BatchingOptions batchingOptions,
        string correlationUuid,
        string onBehalf,
        string signature
    )
    {
        _guaranteed = guaranteed;
        _minAcks = minAcks;
        _inMemoryAcks = inMemoryAcks;
        _minHashAcks = minHashAcks;
        _writeTimeoutSec = writeTimeoutSec;
        _allowDistribute = allowDistribute;
        _signOnChain = signOnChain;
        _syncSigning = syncSigning;
        _allowRemoteBatching = allowRemoteBatching;
        _allowLocalBatching = allowLocalBatching;
        _batchingOptions = batchingOptions;
        _correlationUuid = correlationUuid;
        _onBehalf = onBehalf;
        _signature = signature;
    }

    private string _correlationUuid;
    private string _onBehalf;
    private string _signature;

    public static WriteOptions Default = new WriteOptions(
        DefaultGuaranteedDelivery,
        DefaultMinAcks,
        DefaultMemoryAcks,
        DefaultHashAcks,
        DefaultWriteTimeoutSec,
        true,
        true,
        true,
        false,
        false,
        BatchingOptions.DEFAULT_BATCHING,
        null,
        null,
        null
    );
}
