namespace weaveapi;

public class CreateOptions
{
    public static int DEFAULT_TIMEOUT_SEC = 60;

    public static int PEER_CREATE_TIMEOUT_SEC = 10;

    public static CreateOptions DEFAULT = new CreateOptions(true, true, null, DEFAULT_TIMEOUT_SEC);

    public static CreateOptions FAILSAFE = new CreateOptions(
        false,
        true,
        null,
        DEFAULT_TIMEOUT_SEC
    );

    private bool _failIfExists;

    private bool _replicate;

    private DataLayout _layout;

    private int _createTimeoutSec;

    public CreateOptions(bool failIfExists, bool replicate, DataLayout layout, int createTimeoutSec)
    {
        _failIfExists = failIfExists;
        _replicate = replicate;
        _layout = layout;
        _createTimeoutSec = createTimeoutSec;
    }
}
