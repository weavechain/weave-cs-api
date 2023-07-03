using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace weaveapi;

public class Records
{
    public string Table { get; set; }
    public List<List<object>> Items { get; set; }

    public List<IntegrityWrapper> Integrity { get; set; }

    public Records(string table, List<List<object>> items)
    {
        Table = table;
        Items = items;
    }

    public class IntegrityWrapper
    {
        public string IntervalStart { get; set; }

        [JsonPropertyName("signature")]
        [Required]
        public Dictionary<string, string> Signature { get; set; }

        public IntegrityWrapper(string intervalStart, Dictionary<string, string> signature)
        {
            IntervalStart = intervalStart;
            Signature = signature;
        }
    }
}
