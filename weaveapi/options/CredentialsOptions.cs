namespace weaveapi;

public class CredentialsOptions
{
    public static String JSON_LD = "json-ld";

    public static String JWT = "jwt";

    private int _opTimeoutSec;

    private string _proofType;

    private long _expirationTimestampGMT;

    public CredentialsOptions(int opTimeoutSec, string proofType, long expirationTimestampGMT)
    {
        _opTimeoutSec = opTimeoutSec;
        _proofType = proofType;
        _expirationTimestampGMT = expirationTimestampGMT;
    }
}
