namespace weaveapi;

public class FLOptions
{
    private bool _sync;

    private int _timeoutSec;

    private int _peersConsensus;

    private string _scopes; //needed only when using consensus

    private Dictionary<String, Object> _parameters;

    public FLOptions(bool sync, int timeoutSec, int peerConsensus, string scopes)
    {
        _sync = sync;
        _timeoutSec = timeoutSec;
        _peersConsensus = peerConsensus;
        _scopes = scopes;
    }
}
