namespace weaveapi;

public class DeployOptions
{
    private bool _sync;

    private int _timeoutSec;

    private Dictionary<string, object> _parameters;

    public DeployOptions(bool sync, int timeoutSec, Dictionary<string, object> parameters)
    {
        _sync = sync;
        _timeoutSec = timeoutSec;
        _parameters = parameters;
    }
}
