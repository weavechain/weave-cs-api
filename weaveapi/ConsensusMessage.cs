namespace weaveapi;

public class ConsensusMessage
{
    private string scope;
    private string table;
    private object data;

    public ConsensusMessage(string scope, string table, object data)
    {
        this.scope = scope;
        this.table = table;
        this.data = data;
    }

    public string GetScope()
    {
        return scope;
    }

    public string GetTable()
    {
        return table;
    }

    public object GetData()
    {
        return data;
    }
}
