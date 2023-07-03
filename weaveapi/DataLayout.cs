using System.Text.Json;

namespace weaveapi;

public class DataLayout
{
    private readonly List<object> _types;

    public DataLayout(string json)
    {
        var fieldsMap = JsonSerializer.Deserialize<Dictionary<string, object>>(
            JsonSerializer.Deserialize<Dictionary<string, object>>(
                JsonSerializer.Deserialize<Dictionary<string, object>>(
                    JsonSerializer.Deserialize<Dictionary<string, object>>(json)["data"].ToString()
                )["layout"].ToString()
            )["layout"].ToString()
        );
        _types = fieldsMap.Values.ToList();
    }

    public List<object> GetTypes()
    {
        return _types;
    }
}
