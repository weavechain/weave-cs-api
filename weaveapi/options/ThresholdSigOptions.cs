namespace weaveapi;

public class ThresholdSigOptions
{
    public static int DEFAULT_THRESHOLD_SIG_TIMEOUT_SEC = 300;
    public static ThresholdSigOptions DEFAULT = new ThresholdSigOptions(
        DEFAULT_THRESHOLD_SIG_TIMEOUT_SEC
    );
    private int _thresholdSigTimeoutSec;

    public ThresholdSigOptions(int thresholdSigTimeoutSec)
    {
        _thresholdSigTimeoutSec = thresholdSigTimeoutSec;
    }
}
