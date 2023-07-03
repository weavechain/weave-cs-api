namespace weaveapi;

public class PublishTaskOptions
{
    private int _computeTimeoutSec;

    private Dictionary<string, object> _parameters;

    private bool _allowCustomParams;

    public PublishTaskOptions(
        int computeTimeoutSec,
        Dictionary<string, object> parameters,
        bool allowCustomParams
    )
    {
        _computeTimeoutSec = computeTimeoutSec;
        _parameters = parameters;
        _allowCustomParams = allowCustomParams;
    }
}
