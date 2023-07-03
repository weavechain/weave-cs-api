namespace weaveapi;

public class DeleteOptions
{
    private bool _allowDistribute;

    private string _correlationUuid;

    public static DeleteOptions DELETE_DEFAULT = new DeleteOptions(true, null);

    public DeleteOptions(bool allowDistribute, string correlationUuid)
    {
        _allowDistribute = allowDistribute;
        _correlationUuid = correlationUuid;
    }
}
