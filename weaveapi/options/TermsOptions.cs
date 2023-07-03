namespace weaveapi;

public class TermsOptions
{
    public static TermsOptions AGREE = new TermsOptions(true, true);

    public static TermsOptions DISAGREE = new TermsOptions(false, false);
    private Boolean _agreeTerms;

    private Boolean _agreePrivacyPolicy;

    public TermsOptions(Boolean agreeTerms, Boolean agreePrivacyPolicy)
    {
        _agreeTerms = agreeTerms;
        _agreePrivacyPolicy = agreePrivacyPolicy;
    }
}
