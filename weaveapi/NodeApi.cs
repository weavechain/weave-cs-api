using BigInteger = System.Numerics.BigInteger;

namespace weaveapi
{
    public class NodeApi
    {
        private readonly IWeaveApiClient _weaveApiClient;

        public NodeApi(HttpClientConfig httpClientConfig)
        {
            _weaveApiClient = new WeaveHttpApiClient(httpClientConfig);
        }

        public NodeApi(WsClientConfig wsClientConfig)
        {
            _weaveApiClient = new WeaveWsApiClient(wsClientConfig);
        }

        public async Task Init()
        {
            await _weaveApiClient.Init();
        }

        public async Task<Session> Login(string organization, string account, string scopes)
        {
            var res = await _weaveApiClient.Login(organization, account, scopes);
            return res;
        }

        private async Task<string> PublicKey()
        {
            return await _weaveApiClient.PublicKey();
        }

        public async Task<string> CreateTable(Session session, string scope, string table)
        {
            return await _weaveApiClient.CreateTable(session, scope, table, null);
        }

        public async Task<string> Write(
            Session session,
            string scope,
            Records records,
            WriteOptions writeOptions
        )
        {
            return await _weaveApiClient.Write(session, scope, records, writeOptions);
        }

        public async Task<string> Read(
            Session session,
            string scope,
            string table,
            Filter filter,
            ReadOptions readOptions
        )
        {
            return await _weaveApiClient.Read(session, scope, table, filter, readOptions);
        }

        private async Task<string> Ping()
        {
            return await _weaveApiClient.Ping();
        }

        public async Task<string> Version()
        {
            return await _weaveApiClient.Version();
        }

        public async Task<string> SigKey()
        {
            return await _weaveApiClient.SigKey();
        }

        public async Task<string> Status(Session session)
        {
            return await _weaveApiClient.Status(session);
        }

        public async Task<string> Logout(Session session)
        {
            return await _weaveApiClient.Logout(session);
        }

        public async Task<string> DropTable(
            Session session,
            string scope,
            string table,
            DropOptions dropOptions
        )
        {
            return await _weaveApiClient.DropTable(session, scope, table, dropOptions);
        }

        public async Task<string> Delete(
            Session session,
            string scope,
            string table,
            Filter filter,
            DeleteOptions deleteOptions
        )
        {
            return await _weaveApiClient.Delete(session, scope, table, filter, deleteOptions);
        }

        public async Task<string> Hashes(
            Session session,
            string scope,
            string table,
            Filter filter,
            ReadOptions readOptions
        )
        {
            return await _weaveApiClient.Hashes(session, scope, table, filter, readOptions);
        }

        public async Task<string> DownloadTable(
            Session session,
            string scope,
            string table,
            Filter filter,
            FileFormat format,
            ReadOptions readOptions
        )
        {
            return await _weaveApiClient.DownloadTable(
                session,
                scope,
                table,
                filter,
                format,
                readOptions
            );
        }

        public async Task<string> PublishDataset(
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
        )
        {
            return await _weaveApiClient.PublishDataset(
                session,
                did,
                name,
                description,
                license,
                metadata,
                weave,
                fullDescription,
                logo,
                category,
                scope,
                table,
                filter,
                format,
                price,
                token,
                options
            );
        }

        public async Task<string> DownloadDataset(
            Session session,
            string did,
            ReadOptions readOptions
        )
        {
            return await _weaveApiClient.DownloadDataset(session, did, readOptions);
        }

        public async Task<string> Subscribe(
            Session session,
            string scope,
            string table,
            Filter filter,
            SubscribeOptions subscribeOptions,
            Action<string, Records> updateHandler
        )
        {
            return await _weaveApiClient.Subscribe(
                session,
                scope,
                table,
                filter,
                subscribeOptions,
                updateHandler
            );
        }

        public async Task<string> Unsubscribe(Session session, string subscriptionId)
        {
            return await _weaveApiClient.Unsubscribe(session, subscriptionId);
        }

        public async Task<string> Compute(Session session, string image, ComputeOptions options)
        {
            return await _weaveApiClient.Compute(session, image, options);
        }

        public async Task<string> Flearn(Session session, string image, FLOptions options)
        {
            return await _weaveApiClient.FLearn(session, image, options);
        }

        public async Task<string> HeGetInputs(
            Session session,
            List<object> datasources,
            List<object> args
        )
        {
            return await _weaveApiClient.HEGetInputs(session, datasources, args);
        }

        public async Task<string> HeGetOutputs(Session session, string encoded, List<object> args)
        {
            return await _weaveApiClient.HEGetOutputs(session, encoded, args);
        }

        public async Task<string> HeEncode(Session session, List<object> items)
        {
            return await _weaveApiClient.HEEncode(session, items);
        }

        public async Task<string> Mpc(
            Session session,
            string scope,
            string table,
            string algo,
            List<string> fields,
            Filter filter,
            MPCOptions options
        )
        {
            return await _weaveApiClient.Mpc(session, scope, table, algo, fields, filter, options);
        }

        public async Task<string> StorageProof(
            Session session,
            string scope,
            string table,
            Filter filter,
            string challenge,
            ReadOptions options
        )
        {
            return await _weaveApiClient.StorageProof(
                session,
                scope,
                table,
                filter,
                challenge,
                options
            );
        }

        public async Task<string> ZkStorageProof(
            Session session,
            string scope,
            string table,
            Filter filter,
            string challenge,
            ReadOptions options
        )
        {
            return await _weaveApiClient.ZkStorageProof(
                session,
                scope,
                table,
                filter,
                challenge,
                options
            );
        }

        public async Task<string> VerifySignature(
            Session session,
            string publicKey,
            string signature,
            string data
        )
        {
            return await _weaveApiClient.VerifySignature(session, publicKey, signature, data);
        }

        public async Task<string> ZkProof(
            Session session,
            string scope,
            string table,
            string gadgetType,
            string gadgetParams,
            List<string> fields,
            Filter filter,
            ZKOptions options
        )
        {
            return await _weaveApiClient.ZkProof(
                session,
                scope,
                table,
                gadgetType,
                gadgetParams,
                fields,
                filter,
                options
            );
        }

        public async Task<string> ZkDataProof(
            Session session,
            string gadgetType,
            string gadgetParams,
            List<object> values,
            ZKOptions options
        )
        {
            return await _weaveApiClient.ZkDataProof(
                session,
                gadgetType,
                gadgetParams,
                values,
                options
            );
        }

        public async Task<string> TaskLineage(Session session, string taskId)
        {
            return await _weaveApiClient.TaskLineage(session, taskId);
        }

        public async Task<string> VerifyTaskLineage(
            Session session,
            Dictionary<string, object> lineageData
        )
        {
            return await _weaveApiClient.VerifyTaskLineage(session, lineageData);
        }

        public async Task<string> TaskOutputData(
            Session session,
            string taskId,
            OutputOptions options
        )
        {
            return await _weaveApiClient.TaskOutputData(session, taskId, options);
        }

        public async Task<string> History(
            Session session,
            string scope,
            string table,
            Filter filter,
            HistoryOptions historyOptions
        )
        {
            return await _weaveApiClient.History(session, scope, table, filter, historyOptions);
        }

        public async Task<string> Writers(
            Session session,
            string scope,
            string table,
            Filter filter
        )
        {
            return await _weaveApiClient.Writers(session, scope, table, filter);
        }

        public async Task<string> Tasks(Session session, string scope, string table, Filter filter)
        {
            return await _weaveApiClient.Tasks(session, scope, table, filter);
        }

        public async Task<string> Lineage(
            Session session,
            string scope,
            string table,
            Filter filter
        )
        {
            return await _weaveApiClient.Lineage(session, scope, table, filter);
        }

        public async Task<string> DeployOracle(
            Session session,
            string oracleType,
            string targetBlockchain,
            DeployOptions options
        )
        {
            return await _weaveApiClient.DeployOracle(
                session,
                oracleType,
                targetBlockchain,
                options
            );
        }

        public async Task<string> DeployFeed(Session session, string image, DeployOptions options)
        {
            return await _weaveApiClient.DeployFeed(session, image, options);
        }

        public async Task<string> RemoveFeed(Session session, string feedId)
        {
            return await _weaveApiClient.RemoveFeed(session, feedId);
        }

        public async Task<string> StartFeed(Session session, string feedId, ComputeOptions options)
        {
            return await _weaveApiClient.StartFeed(session, feedId, options);
        }

        public async Task<string> StopFeed(Session session, string feedId)
        {
            return await _weaveApiClient.StopFeed(session, feedId);
        }

        public async Task<string> IssueCredentials(
            Session session,
            string issuer,
            string holder,
            Dictionary<string, object> credentials,
            CredentialsOptions options
        )
        {
            return await _weaveApiClient.IssueCredentials(
                session,
                issuer,
                holder,
                credentials,
                options
            );
        }

        public async Task<string> VerifyCredentials(
            Session session,
            Dictionary<string, object> credentials,
            CredentialsOptions options
        )
        {
            return await _weaveApiClient.VerifyCredentials(session, credentials, options);
        }

        public async Task<string> CreatePresentation(
            Session session,
            Dictionary<string, object> credentials,
            string subject,
            CredentialsOptions options
        )
        {
            return await _weaveApiClient.CreatePresentation(session, credentials, subject, options);
        }

        public async Task<string> SignPresentation(
            Session session,
            Dictionary<string, object> presentation,
            string domain,
            string challenge,
            CredentialsOptions options
        )
        {
            return await _weaveApiClient.SignPresentation(
                session,
                presentation,
                domain,
                challenge,
                options
            );
        }

        public async Task<string> VerifyPresentation(
            Session session,
            Dictionary<string, object> signedPresentation,
            string domain,
            string challenge,
            CredentialsOptions options
        )
        {
            return await _weaveApiClient.VerifyPresentation(
                session,
                signedPresentation,
                domain,
                challenge,
                options
            );
        }

        public async Task<string> PostMessage(
            Session session,
            string targetInboxKey,
            string message,
            MessageOptions options
        )
        {
            return await _weaveApiClient.PostMessage(session, targetInboxKey, message, options);
        }

        public async Task<string> PollMessages(
            Session session,
            string inboxKey,
            MessageOptions options
        )
        {
            return await _weaveApiClient.PollMessages(session, inboxKey, options);
        }

        public async Task<string> GetSidechainDetails(Session session)
        {
            return await _weaveApiClient.GetSidechainDetails(session);
        }

        public async Task<string> GetNodes(Session session)
        {
            return await _weaveApiClient.GetNodes(session);
        }

        public async Task<string> GetScopes(Session session)
        {
            return await _weaveApiClient.GetScopes(session);
        }

        public async Task<string> GetTables(Session session, string scope)
        {
            return await _weaveApiClient.GetTables(session, scope);
        }

        public async Task<string> GetTableDefinition(Session session, string scope, string table)
        {
            return await _weaveApiClient.GetTableDefinition(session, "get_table_definition", table);
        }

        public async Task<string> GetNodeConfig(Session session, string nodePublicKey)
        {
            return await _weaveApiClient.GetNodeConfig(session, nodePublicKey);
        }

        public async Task<string> GetAccountNotifications(Session session)
        {
            return await _weaveApiClient.GetAccountNotifications(session);
        }

        public async Task<string> UpdateLayout(
            Session session,
            string scope,
            string table,
            string layout
        )
        {
            return await _weaveApiClient.UpdateLayout(session, scope, table, layout);
        }

        public async Task<string> UpdateConfig(
            Session session,
            string path,
            Dictionary<string, object> values
        )
        {
            return await _weaveApiClient.UpdateConfig(session, path, values);
        }

        public async Task<string> Balance(
            Session session,
            string accountAddress,
            string scope,
            string token
        )
        {
            return await _weaveApiClient.Balance(session, accountAddress, scope, token);
        }

        public async Task<string> Transfer(
            Session session,
            string accountAddress,
            string scope,
            string token,
            double amount
        )
        {
            return await _weaveApiClient.Transfer(session, accountAddress, scope, token, amount);
        }

        public async Task<string> Call(
            Session session,
            string contractAddress,
            string scope,
            string fn,
            byte[] data,
            ChainOptions options
        )
        {
            return await _weaveApiClient.Call(session, contractAddress, scope, fn, data, options);
        }

        public async Task<string> UpdateFees(Session session, string scope, string fees)
        {
            return await _weaveApiClient.UpdateFees(session, scope, fees);
        }

        public async Task<string> ContractState(
            Session session,
            string contractAddress,
            string scope
        )
        {
            return await _weaveApiClient.ContractState(session, contractAddress, scope);
        }

        public async Task<string> UpdateFee(Session session, string scope, string fees)
        {
            return await _weaveApiClient.UpdateFees(session, scope, fees);
        }

        public async Task<string> ResetConfig(Session session)
        {
            return await _weaveApiClient.ResetConfig(session);
        }

        public async Task<string> Withdraw(Session session, string token, BigInteger amount)
        {
            return await _weaveApiClient.Withdraw(session, token, amount);
        }
    }
}
