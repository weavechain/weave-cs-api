namespace weaveapi;

public enum FileFormat
{
    //generic unformatted file (limited functionality)
    file,

    //raw (uncompressed) binary encoding of records
    raw,

    //raw (uncompressed) binary encoding, one file per record.
    //   Can be used with multiple columns, only one STRING as last column, but original intent is to publish image files as a single base64 encoded field
    encoded_file,

    csv,

    avro,

    json,

    parquet,

    feather,

    orc,

    toml,

    yaml,

    protobuf
}
