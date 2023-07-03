namespace weaveapi;

public class PublishDatasetOptions
{
    public static int ALL_ACTIVE = Int32.MaxValue;

    public static string SNAPSHOT = "snapshot"; //data as at publish time, a snapshot is stored in the marketplace DB/file system

    public static string LIVE_SNAPSHOT = "live"; //data as at download time, no snapshot is stored at publish time

    public static string ROLLING = "rolling";

    public static List<string> TYPES = new List<string> { "SNAPSHOT", "LIVE_SNAPSHOT", "ROLLING" };
    private string _type;

    private string _rollingUnit;

    private string _rollingCount;

    private bool _verifyHash;

    private int _readTimeoutSec;

    private int _apiUrlpeersConsensus;

    private bool _enableMux;

    private bool _includeCached;

    private bool _verifySourceSignature;

    public PublishDatasetOptions(
        string type,
        string rollingUnit,
        string rollingCount,
        bool verifyHash,
        int readTimeoutSec,
        int apiUrlpeersConsensus,
        bool enableMux,
        bool includeCached,
        bool verifySourceSignature
    )
    {
        _type = type;
        _rollingUnit = rollingUnit;
        _rollingCount = rollingCount;
        _verifyHash = verifyHash;
        _readTimeoutSec = readTimeoutSec;
        _apiUrlpeersConsensus = apiUrlpeersConsensus;
        _enableMux = enableMux;
        _includeCached = includeCached;
        _verifySourceSignature = verifySourceSignature;
    }
}
