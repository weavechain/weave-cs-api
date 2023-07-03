namespace weaveapi;

public class DropOptions
{
    public static int DEFAULT_TIMEOUT_SEC = 60;

    public static int PEER_DROP_TIMEOUT_SEC = 10;

    public static DropOptions DEFAULT = new DropOptions(true, false, DEFAULT_TIMEOUT_SEC);

    public static DropOptions FAILSAFE = new DropOptions(false, false, DEFAULT_TIMEOUT_SEC);

    private bool _failIfNotExists;

    private bool _replicate;

    private int _dropTimeoutSec;

    public DropOptions(bool failIfNotExists, bool replicate, int dropTimeoutSec)
    {
        _failIfNotExists = failIfNotExists;
        _replicate = replicate;
        _dropTimeoutSec = dropTimeoutSec;
    }
}
