namespace weaveapi;

public class SplitLearnOptions
{
    public static int DEFAULT_SL_TIMEOUT_SEC = 300;

    public static int DEFAULT_MAX_BATCH_SIZE = 1;

    public static SplitLearnOptions DEFAULT = new SplitLearnOptions(
        false,
        DEFAULT_SL_TIMEOUT_SEC,
        0,
        null,
        ALL_ACTIVE_NODES,
        null
    );

    private static string WILDCARD = "*";

    public static List<string> ALL_ACTIVE_NODES = new List<string>() { WILDCARD };

    private bool _sync;

    private int _timeoutSec;

    private int _minParticipants;

    private string _scopes; //needed only when using consensus

    private List<string> _sources;

    private Dictionary<string, object> _parameters;

    public SplitLearnOptions(
        bool sync,
        int timeoutSec,
        int minParticipants,
        string scopes,
        List<string> sources,
        Dictionary<string, object> parameters
    )
    {
        _sync = sync;
        _timeoutSec = timeoutSec;
        _minParticipants = minParticipants;
        _scopes = scopes;
        _sources = sources;
        _parameters = parameters;
    }
}
