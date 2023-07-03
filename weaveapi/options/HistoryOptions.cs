namespace weaveapi;

public class HistoryOptions
{
    private List<string> _operationTypes = new();

    public HistoryOptions WithOperationTypes(List<string> operationTypes)
    {
        _operationTypes.AddRange(operationTypes);
        return this;
    }
}
