namespace weaveapi;

public class BatchingOptions
{
    public static BatchingOptions DEFAULT_NO_BATCHING = new BatchingOptions(0, 0, 0);

    public static BatchingOptions DEFAULT_BATCHING = new BatchingOptions(10000, 1048576, 250);

    public static int INITIAL_HASHING_BATCHES = 10_000;

    private int _waitRecords = 0;
    private int _waitSize = 0;
    private int _waitTimeMs = 0;

    public BatchingOptions(int waitRecords, int waitSize, int waitTimeMs)
    {
        _waitRecords = waitRecords;
        _waitSize = waitSize;
        _waitTimeMs = waitTimeMs;
    }
}
