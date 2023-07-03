namespace weaveapi;

public class SubscribeOptions
{
    public static int DEFAULT_SUBSCRIBE_TIMEOUT_SEC = 300;

    public static int DEFAULT_MAX_BATCH_SIZE = 1;

    public static SubscribeOptions DEFAULT = new SubscribeOptions(
        true,
        true,
        DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
        false,
        BatchingOptions.DEFAULT_BATCHING
    );

    public static SubscribeOptions DEFAULT_NO_BATCHING = new SubscribeOptions(
        true,
        true,
        DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
        false,
        BatchingOptions.DEFAULT_NO_BATCHING
    );

    public static SubscribeOptions DEFAULT_NO_CHAIN = new SubscribeOptions(
        false,
        true,
        DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
        false,
        BatchingOptions.DEFAULT_BATCHING
    );

    public static SubscribeOptions DEFAULT_NO_CHAIN_NO_BATCHING = new SubscribeOptions(
        false,
        true,
        DEFAULT_SUBSCRIBE_TIMEOUT_SEC,
        false,
        BatchingOptions.DEFAULT_NO_BATCHING
    );
    private bool _verifyHash;

    private bool _initialSnapshot;

    private int _readTimeoutSec;

    private bool _externalUpdates;

    private BatchingOptions _batchingOptions;

    public SubscribeOptions(
        bool veifyHash,
        bool initialSnapshot,
        int readTimeoutSec,
        bool externalUpdates,
        BatchingOptions batchingOptions
    )
    {
        _verifyHash = veifyHash;
        _initialSnapshot = initialSnapshot;
        _readTimeoutSec = readTimeoutSec;
        _externalUpdates = externalUpdates;
        _batchingOptions = batchingOptions;
    }
}
