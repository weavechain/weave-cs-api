namespace weaveapi;

public class ComputeOptions
{
    public static int DEFAULT_COMPUTE_TIMEOUT_SEC = 300;
    public static int DEFAULT_MAX_BATCH_SIZE = 1;
    public static ComputeOptions DEFAULT = new ComputeOptions(
        false,
        DEFAULT_COMPUTE_TIMEOUT_SEC,
        0,
        null,
        null,
        null,
        null
    );
    public static int ALL_ACTIVE_PEERS = Int32.MaxValue;
    private bool _sync;

    private int _timeoutSec;

    private int _peersConsensus;

    private string _scopes; //needed only when using consensus

    private Dictionary<string, object> _parameters;

    private string _onBehalf;

    private string _signature;

    public ComputeOptions(
        bool sync,
        int timeoutSec,
        int peerConsensus,
        string scopes,
        Dictionary<string, object> parameters,
        string onBehalf,
        string signature
    )
    {
        _sync = sync;
        _timeoutSec = timeoutSec;
        _peersConsensus = peerConsensus;
        _scopes = scopes;
        _parameters = parameters;
        _onBehalf = onBehalf;
        _signature = signature;
    }
}
