namespace weaveapi;

public class MessageOptions
{
    private int _opTimeoutSec;

    private int _ttlSec;

    public MessageOptions(int opTimeoutSec, int ttlSec)
    {
        _opTimeoutSec = opTimeoutSec;
        _ttlSec = ttlSec;
    }
}
