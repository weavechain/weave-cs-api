namespace weaveapi;

public class ProxyEncryptedData
{
    private byte[] _encoded;

    private byte[] _reencryptionKey;

    private byte[] _writerSignPubKey;

    private byte[] _readerPubKey;

    public ProxyEncryptedData(
        byte[] encoded,
        byte[] reencryptionKey,
        byte[] writerSignPubKey,
        byte[] readerPubKey
    )
    {
        _encoded = encoded;
        _reencryptionKey = reencryptionKey;
        _writerSignPubKey = writerSignPubKey;
        _readerPubKey = readerPubKey;
    }
}
