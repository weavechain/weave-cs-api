using System.Numerics;
using weaveapi;

interface IWeaveApiClient
{
    Task Init();
    Task<Session> Login(string organization, string account, string scopes);
    Task<string> PublicKey();
    Task<string> CreateTable(
        Session session,
        string scope,
        string table,
        CreateOptions createOptions
    );
    Task<string> Write(Session session, string scope, Records records, WriteOptions writeOptions);
    Task<string> Read(
        Session session,
        string scope,
        string table,
        Filter filter,
        ReadOptions readOptions
    );
    Task<string> Ping();
    Task<string> Version();
    Task<string> SigKey();
    Task<string> Status(Session session);
    Task<string> Logout(Session session);
    Task<string> DropTable(Session session, string scope, string table, DropOptions dropOptions);
    Task<string> Delete(
        Session session,
        string scope,
        string table,
        Filter filter,
        DeleteOptions deleteOptions
    );
    Task<string> Hashes(
        Session session,
        string scope,
        string table,
        Filter filter,
        ReadOptions readOptions
    );
    Task<string> DownloadTable(
        Session session,
        string scope,
        string table,
        Filter filter,
        FileFormat format,
        ReadOptions readOptions
    );
    Task<string> PublishDataset(
        Session session,
        string did,
        string name,
        string description,
        string license,
        string metadata,
        string weave,
        string fullDescription,
        string logo,
        string category,
        string scope,
        string table,
        Filter filter,
        FileFormat format,
        double price,
        string token,
        PublishDatasetOptions options
    );
    Task<string> DownloadDataset(Session session, string did, ReadOptions readOptions);
    Task<string> Subscribe(
        Session session,
        string scope,
        string table,
        Filter filter,
        SubscribeOptions subscribeOptions,
        Action<string, Records> updateHandler
    );
    Task<string> Unsubscribe(Session session, string subscriptionId);
    Task<string> Compute(Session session, string image, ComputeOptions options);
    Task<string> FLearn(Session session, string image, FLOptions options);
    Task<string> HEGetInputs(Session session, List<object> datasources, List<object> args);
    Task<string> HEGetOutputs(Session session, string encoded, List<object> args);
    Task<string> HEEncode(Session session, List<object> items);
    Task<string> Mpc(
        Session session,
        string scope,
        string table,
        string algo,
        List<string> fields,
        Filter filter,
        MPCOptions options
    );
    Task<string> StorageProof(
        Session session,
        string scope,
        string table,
        Filter filter,
        string challenge,
        ReadOptions options
    );
    Task<string> ZkStorageProof(
        Session session,
        string scope,
        string table,
        Filter filter,
        string challenge,
        ReadOptions options
    );
    Task<string> VerifySignature(Session session, string publicKey, string signature, string data);
    Task<string> ZkProof(
        Session session,
        string scope,
        string table,
        string gadgetType,
        string gadgetParams,
        List<string> fields,
        Filter filter,
        ZKOptions options
    );
    Task<string> ZkDataProof(
        Session session,
        string gadgetType,
        string gadgetParams,
        List<object> values,
        ZKOptions options
    );
    Task<string> TaskLineage(Session session, string taskId);
    Task<string> VerifyTaskLineage(Session session, Dictionary<string, object> lineageData);
    Task<string> TaskOutputData(Session session, string taskId, OutputOptions options);
    Task<string> History(
        Session session,
        string scope,
        string table,
        Filter filter,
        HistoryOptions historyOptions
    );
    Task<string> Writers(Session session, string scope, string table, Filter filter);
    Task<string> Tasks(Session session, string scope, string table, Filter filter);
    Task<string> Lineage(Session session, string scope, string table, Filter filter);
    Task<string> DeployOracle(
        Session session,
        string oracleType,
        string targetBlockchain,
        DeployOptions options
    );
    Task<string> DeployFeed(Session session, string image, DeployOptions options);
    Task<string> RemoveFeed(Session session, string feedId);
    Task<string> StartFeed(Session session, string feedId, ComputeOptions options);
    Task<string> StopFeed(Session session, string feedId);
    Task<string> IssueCredentials(
        Session session,
        string issuer,
        string holder,
        Dictionary<string, object> credentials,
        CredentialsOptions options
    );
    Task<string> VerifyCredentials(
        Session session,
        Dictionary<string, object> credentials,
        CredentialsOptions options
    );
    Task<string> CreatePresentation(
        Session session,
        Dictionary<string, object> credentials,
        string subject,
        CredentialsOptions options
    );
    Task<string> SignPresentation(
        Session session,
        Dictionary<string, object> presentation,
        string domain,
        string challenge,
        CredentialsOptions options
    );
    Task<string> VerifyPresentation(
        Session session,
        Dictionary<string, object> signedPresentation,
        string domain,
        string challenge,
        CredentialsOptions options
    );
    Task<string> PostMessage(
        Session session,
        string targetInboxKey,
        string message,
        MessageOptions options
    );
    Task<string> PollMessages(Session session, string inboxKey, MessageOptions options);
    Task<string> GetSidechainDetails(Session session);
    Task<string> GetNodes(Session session);
    Task<string> GetScopes(Session session);
    Task<string> GetTables(Session session, string scope);
    Task<string> GetTableDefinition(Session session, string scope, string table);
    Task<string> GetNodeConfig(Session session, string nodePublicKey);
    Task<string> GetAccountNotifications(Session session);
    Task<string> UpdateLayout(Session session, string scope, string table, string layout);
    Task<string> UpdateConfig(Session session, string path, Dictionary<string, object> values);
    Task<string> Balance(Session session, string accountAddress, string scope, string token);
    Task<string> Transfer(
        Session session,
        string accountAddress,
        string scope,
        string token,
        double amount
    );
    Task<string> Call(
        Session session,
        string contractAddress,
        string scope,
        string fn,
        byte[] data,
        ChainOptions options
    );
    Task<string> UpdateFees(Session session, string scope, string fees);
    Task<string> ContractState(Session session, string contractAddress, string scope);
    Task<string> UpdateFee(Session session, string scope, string fees);
    Task<string> ResetConfig(Session session);
    Task<string> Withdraw(Session session, string token, BigInteger amount);
    Task<string> HashCheckpoint(Session session, Boolean enable);
    Task<string> HashCheckpoint(Session session);
    Task<string> BlindSignature(Session session, string blinded);
    Task<string> BlsKey();
    Task<string> BroadCast(Session session, ConsensusMessage message);
    Task<string> Count(
        Session session,
        string scope,
        string table,
        Filter filter,
        ReadOptions options
    );
    Task<string> CreateAccount(Session session, string pulicKey, ChainOptions options);
    Task<string> EmailAuth(
        string organization,
        string clientPubKey,
        string targetEmail,
        string targetWebUrl
    );
    Task<string> EnableProduct(Session session, string did, string productType, Boolean active);
    Task<string> GrantRole(Session session, string account, HashSet<string> roles);
    Task<string> PluginCall(
        Session session,
        string plugin,
        string request,
        Dictionary<string, Object> args,
        int timeoutSec
    );
    Task<string> ProofsLastHash(Session session, string scope, string table);
    Task<string> ProxyEncryptSecret(
        Session session,
        string scope,
        string table,
        ProxyEncryptedData pre
    );
    Task<string> ProxyReEncryptSecret(Session session, string scope, string table);
    Task<string> RsaKey();
    Task<string> splitLearn(Session session, string image, SplitLearnOptions options);
    Task<string> UpdateProofs(Session session, string scope, string table);
    Task<string> UploadApi(Session session, Dictionary<string, Object> parameters);
    Task<string> WithdrawAuthorize(Session session, string token, string address);
}
