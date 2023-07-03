namespace weaveapi;

public class ChainOptions
{
    public static int DEFAULT_OP_TIMEOUT_SEC = 300;
    public static ChainOptions DEFAULT = new ChainOptions(DEFAULT_OP_TIMEOUT_SEC);
    private int _opTimeoutSec;

    public ChainOptions(int opTimeoutSec)
    {
        _opTimeoutSec = opTimeoutSec;
    }
}
