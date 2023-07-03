using System.Collections.Concurrent;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Utilities.Encoders;
using SimpleBase;
using weaveapi;
using Websocket.Client;

public class WeaveWsApiClient : IWeaveApiClient
{
    private WebsocketClient _wsClient;
    private readonly ApiContext _apiContext;
    private readonly JsonSerializerOptions _serializeOptions =
        new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };

    private ConcurrentDictionary<string, Task<string>> pendingTasks = new();
    private ConcurrentDictionary<string, Dictionary<string, object>> pendingResponses = new();

    public WeaveWsApiClient(WsClientConfig config)
    {
        _apiContext = new ApiContext(config);

        var _apiUrl = GetApiUrl(config);
        var uri = new Uri(_apiUrl);
        _wsClient = new WebsocketClient(uri);

        _wsClient.MessageReceived.Subscribe(msg =>
        {
            Dictionary<string, object> response = JsonSerializer.Deserialize<
                Dictionary<string, object>
            >(msg.ToString());
            string id = response["id"].ToString();
            pendingResponses[id] = response;
            Task<string> t = pendingTasks[id];
            t.RunSynchronously();
        });
    }

    private static string GetApiUrl(WsClientConfig config)
    {
        var protocol = config.isUseWss() ? "wss" : "ws";
        return $"{protocol}://{config.GetHost()}:{config.GetPort()}";
    }

    private static Dictionary<string, object> AddAuthParams(
        Dictionary<string, object> request,
        Session session
    )
    {
        request["x-api-key"] = session.GetApiKey();
        request["x-nonce"] = session.IncrementNonceAndGetString();

        string toSign = GetDataToSign(request);
        byte[] signature = SignUtils.HashHmac(session.GetSecret(), toSign);
        string signatureString = Convert.ToBase64String(signature);
        request["x-sig"] = signatureString;

        return request;
    }

    public static string GetDataToSign(Dictionary<String, Object> request)
    {
        string s = "";

        var keys = new string[]
        {
            "x-api-key",
            "nonce",
            "signature",
            "organization",
            "account",
            "scope",
            "table"
        };
        for (int i = 0; i < keys.Length; i++)
        {
            if (i > 0)
            {
                s = s + "\n";
            }
            if (request.ContainsKey(keys[i]))
            {
                s = s + request[keys[i]];
            }
            else
            {
                s = s + "null";
            }
        }
        return s;
    }

    private Task<string> sendRequest(
        Session? session,
        Dictionary<string, object> request,
        string type,
        bool isAuthenticated
    )
    {
        if (isAuthenticated)
        {
            request = AddAuthParams(request, session);
        }
        request["type"] = type;

        var id = Guid.NewGuid().ToString();
        Func<string> onMessageAction = () =>
        {
            Dictionary<string, object> response = pendingResponses[id];
            Dictionary<string, object> replyMap = JsonSerializer.Deserialize<
                Dictionary<string, object>
            >(response["reply"].ToString());
            string replyMapString = JsonSerializer.Serialize(replyMap);
            return replyMapString;
        };
        Task<string> t = new Task<string>(onMessageAction);
        pendingTasks[id] = t;
        request["id"] = id;
        _wsClient.Send(JsonSerializer.Serialize(request));
        return t;
    }

    public async Task Init()
    {
        await _wsClient.StartOrFail();
        Console.WriteLine("Websocket client started successfully...");

        var serverPublicKeyResponse = await PublicKey();
        _apiContext.SetDecodedServerPubKey(serverPublicKeyResponse);
        _apiContext.ComputeSharedSecret();
    }

    public async Task<string> PublicKey()
    {
        return await sendRequest(null, new Dictionary<string, object>(), "public_key", false);
    }

    public async Task<Session> Login(string organization, string account, string scopes)
    {
        var iv = SignUtils.GenerateIv();
        var toSign = organization + "\n" + account + "\n" + scopes;

        var pubSigKey = new Base58(Base58Alphabet.Bitcoin).Encode(
            _apiContext.GetEdClientPublicKey().GetEncoded()
        );
        var contentDictionary = new Dictionary<string, object>
        {
            ["organization"] = organization,
            ["account"] = account,
            ["scopes"] = scopes,
            ["signature"] = SignUtils
                .GenerateSharedKeySignature(
                    toSign,
                    _apiContext.GetSharedSecret(),
                    iv,
                    _apiContext.GetSeedHex()
                )
                .ToLower(),
            ["x-iv"] = SignUtils.ToHexString(iv),
            ["x-sig-key"] = pubSigKey
        };

        var sessionResponseMessageString = await sendRequest(
            null,
            contentDictionary,
            "login",
            false
        );

        var dataJson = JsonSerializer.Deserialize<Dictionary<string, object>>(
            sessionResponseMessageString
        )["data"].ToString();
        var sessionResponse = JsonSerializer.Deserialize<Dictionary<string, object>>(dataJson);
        var byteArrayIv = SignUtils.HexStringToByteArray(sessionResponse["x-iv"].ToString());
        var byteArraySecret = SignUtils.HexStringToByteArray(sessionResponse["secret"].ToString());
        var decryptedSecret = SignUtils.Decrypt(
            byteArraySecret,
            _apiContext.GetSharedSecret(),
            byteArrayIv,
            _apiContext.GetSeedHex()
        );
        return new Session(sessionResponse, decryptedSecret);
    }

    public async Task<string> CreateTable(
        Session session,
        string scope,
        string table,
        CreateOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["options"] = JsonSerializer.Serialize(options)
            };

            return await sendRequest(session, request, "create", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform CreateTable call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Write(
        Session session,
        string scope,
        Records records,
        WriteOptions writeOptions
    )
    {
        try
        {
            if (session.IsIntegrityChecks())
            {
                DataLayout layout;
                if (session.HasLayoutForKey(scope, records.Table))
                {
                    layout = session.GetDataLayout(scope, records.Table);
                }
                else
                {
                    var layoutResponse = await GetTableDefinition(session, scope, records.Table);
                    var layoutResponseString = layoutResponse;
                    layout = new DataLayout(layoutResponseString);
                    session.CacheLayout(scope, records.Table, layout);
                }

                records.Integrity = SignUtils.GetIntegrity(
                    records,
                    layout,
                    _apiContext.GetSeedHex(),
                    _apiContext.GetEncodedClientPubKey(),
                    _apiContext.GetEdClientPrivateKey()
                );
            }

            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = records.Table,
                ["options"] = JsonSerializer.Serialize(writeOptions),
                ["records"] = JsonSerializer.Serialize(records, _serializeOptions)
            };

            return await sendRequest(session, request, "write", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Write call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GetTableDefinition(Session session, string scope, string table)
    {
        try
        {
            var request = new Dictionary<string, object> { ["scope"] = scope, ["table"] = table };
            return await sendRequest(session, request, "get_table_definition", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GetTableDefinition call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Ping()
    {
        try
        {
            return await sendRequest(null, new Dictionary<string, object>(), "ping", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Ping call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Read(
        Session session,
        string scope,
        string table,
        Filter filter,
        ReadOptions readOptions
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter, _serializeOptions),
                ["options"] = JsonSerializer.Serialize(readOptions, _serializeOptions)
            };

            return await sendRequest(session, request, "read", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Read call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Version()
    {
        try
        {
            return await sendRequest(null, new Dictionary<string, object>(), "version", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Version call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> SigKey()
    {
        try
        {
            return await sendRequest(null, new Dictionary<string, object>(), "sig_key", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform SigKey call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ProxyLogin(
        string node,
        string organization,
        string account,
        string scopes
    )
    {
        try
        {
            return await sendRequest(null, new Dictionary<string, object>(), "proxy_login", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ProxyLogin call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Logout(Session session)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, new Dictionary<string, object>(), "logout", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Logout call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Terms(Session session, TermsOptions options)
    {
        try
        {
            var termsOptions = JsonSerializer.Serialize(options);
            var request = new Dictionary<string, object>
            {
                ["signature"] = SignUtils.SignEd25519(
                    termsOptions,
                    _apiContext.GetEdClientPrivateKey()
                ),
                ["organization"] = session.GetOrganization(),
                ["options"] = termsOptions,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "terms", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Terms call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Status(Session session)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "status", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Status call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> DropTable(
        Session session,
        string scope,
        string table,
        DropOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "drop", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform DropTable call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> UpdateLayout(
        Session session,
        string scope,
        string table,
        string layout
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["layout"] = layout,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "update_layout", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform UpdateLayout call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GetSidechainDetails(Session session)
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "get_sidechain_details",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GetSidechainDetails call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Delete(
        Session session,
        string scope,
        string table,
        Filter filter,
        DeleteOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "delete", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Delete call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Hashes(
        Session session,
        string scope,
        string table,
        Filter filter,
        ReadOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "hashes", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Hashes call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> DownloadTable(
        Session session,
        string scope,
        string table,
        Filter filter,
        FileFormat format,
        ReadOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["format"] = format.ToString(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "download_table", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform DownloadTable call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> DownloadDataset(Session session, string did, ReadOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["did"] = did
            };
            return await sendRequest(session, request, "download_dataset", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform DownloadDataset call: " + e.ToString());
            return "exception: " + e.ToString();
        }
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
        try
        {
            var request = new Dictionary<string, object>
            {
                ["metadata"] = metadata,
                ["format"] = format.ToString(),
                ["description"] = description,
                ["token"] = token,
                ["filter"] = JsonSerializer.Serialize(filter),
                ["license"] = license,
                ["full_description"] = fullDescription,
                ["price"] = price.ToString(CultureInfo.InvariantCulture),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["name"] = name,
                ["options"] = JsonSerializer.Serialize(options),
                ["logo"] = logo,
                ["category"] = category,
                ["account"] = session.GetAccount(),
                ["did"] = did,
                ["weave"] = weave,
                ["table"] = table
            };
            return await sendRequest(session, request, "publish_dataset", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform PublishDataset call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> RunTask(Session session, string did, ComputeOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["did"] = did
            };
            return await sendRequest(session, request, "run_task", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform RunTask call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> PublishTask(
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
        string task,
        double price,
        string token,
        PublishTaskOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["metadata"] = metadata,
                ["description"] = description,
                ["token"] = token,
                ["license"] = license,
                ["full_description"] = fullDescription,
                ["task"] = task,
                ["price"] = price.ToString(CultureInfo.InvariantCulture),
                ["organization"] = session.GetOrganization(),
                ["name"] = name,
                ["options"] = JsonSerializer.Serialize(options),
                ["logo"] = logo,
                ["category"] = category,
                ["account"] = session.GetAccount(),
                ["did"] = did,
                ["weave"] = weave
            };
            return await sendRequest(session, request, "publish_task", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform PublishTask call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Subscribe(
        Session session,
        string scope,
        string table,
        Filter filter,
        SubscribeOptions options,
        Action<string, Records> onData
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "subscribe", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Subscribe call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Unsubscribe(Session session, string subscriptionId)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["subscriptionId"] = subscriptionId,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "unsubscribe", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Unsubscribe call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Compute(Session session, string image, ComputeOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["image"] = image,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "compute", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Compute call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> FLearn(Session session, string image, FLOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["image"] = image,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "f_learn", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform FLearn call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> HEGetInputs(
        Session session,
        List<object> datasources,
        List<object> args
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["args"] = JsonSerializer.Serialize(args),
                ["datasources"] = JsonSerializer.Serialize(datasources),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "he_get_inputs", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform HEGetInputs call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> HEGetOutputs(Session session, string encoded, List<object> args)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["args"] = JsonSerializer.Serialize(args),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["encoded"] = encoded
            };
            return await sendRequest(session, request, "he_get_outputs", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform HEGetOutputs call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> HEEncode(Session session, List<object> items)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["items"] = JsonSerializer.Serialize(items),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "he_encode", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform HEEncode call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ZkProof(
        Session session,
        string scope,
        string table,
        string gadget,
        string gadgetParams,
        List<string> fields,
        Filter filter,
        ZKOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["gadget"] = gadget,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["params"] = gadgetParams,
                ["fields"] = JsonSerializer.Serialize(fields),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "zk_proof", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ZkProof call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ZkDataProof(
        Session session,
        string gadget,
        string gadgetParams,
        List<object> values,
        ZKOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["gadget"] = gadget,
                ["organization"] = session.GetOrganization(),
                ["values"] = JsonSerializer.Serialize(values),
                ["options"] = JsonSerializer.Serialize(options),
                ["params"] = gadgetParams,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "zk_data_proof", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ZkDataProof call: " + e.ToString());
            return "exception: " + e.ToString();
        }
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
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["fields"] = JsonSerializer.Serialize(fields),
                ["account"] = session.GetAccount(),
                ["table"] = table,
                ["algo"] = algo
            };
            return await sendRequest(session, request, "mpc", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Mpc call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> MPCInitProtocol(
        Session session,
        string computationId,
        int nodeIndex,
        string scope,
        string table,
        string algo,
        List<string> fields,
        Filter filter,
        Dictionary<string, int> indexedPeers,
        MPCOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["nodeIndex"] = nodeIndex.ToString(),
                ["fields"] = JsonSerializer.Serialize(fields),
                ["account"] = session.GetAccount(),
                ["table"] = table,
                ["algo"] = algo,
                ["computationId"] = computationId,
                ["indexedPeers"] = JsonSerializer.Serialize(indexedPeers)
            };
            return await sendRequest(session, request, "mpc_init", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform MPCInitProtocol call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> MPCProtocol(Session session, string computationId, string message)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["message"] = message,
                ["account"] = session.GetAccount(),
                ["computationId"] = computationId
            };
            return await sendRequest(session, request, "mpc_proto", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform MPCProtocol call: " + e.ToString());
            return "exception: " + e.ToString();
        }
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
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["challenge"] = challenge,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "storage_proof", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform StorageProof call: " + e.ToString());
            return "exception: " + e.ToString();
        }
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
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["challenge"] = challenge,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "zk_storage_proof", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ZkStorageProof call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> MerkleTree(
        Session session,
        string scope,
        string table,
        Filter filter,
        string salt,
        ReadOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["salt"] = salt,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "merkle_tree", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform MerkleTree call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> MerkleProof(Session session, string scope, string table, string hash)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table,
                ["hash"] = hash
            };
            return await sendRequest(session, request, "merkle_proof", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform MerkleProof call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ZkMerkleTree(
        Session session,
        string scope,
        string table,
        Filter filter,
        string salt,
        int rounds,
        int seed,
        ZKOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["salt"] = salt,
                ["seed"] = seed.ToString(),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table,
                ["rounds"] = rounds.ToString()
            };
            return await sendRequest(session, request, "zk_merkle_tree", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ZkMerkleTree call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> RootHash(Session session, string scope, string table)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "root_hash", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform RootHash call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> VerifySignature(
        Session session,
        string publicKey,
        string signature,
        string data
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["data"] = data,
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
            };
            return await sendRequest(session, request, "verify_data_signature", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform VerifySignature call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GetNodes(Session session)
    {
        try
        {
            return await sendRequest(session, new Dictionary<string, object>(), "get_nodes", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GetNodes call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> TaskLineage(Session session, string taskId)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["taskId"] = taskId
            };
            return await sendRequest(session, request, "task_lineage", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform TaskLineage call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> HashCheckpoint(Session session, bool enable)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["enable"] = enable.ToString(),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "hash_checkpoint", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform HashCheckpoint call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> HashCheckpoint(Session session)
    {
        try
        {
            return await HashCheckpoint(session, false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform HashCheckpoint call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> VerifyTaskLineage(
        Session session,
        Dictionary<string, object> metadata
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["metadata"] = JsonSerializer.Serialize(metadata),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "verify_task_lineage", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform HashCheckpoint call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> TaskOutputData(Session session, string taskId, OutputOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["taskId"] = taskId
            };
            return await sendRequest(session, request, "task_output_data", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform TaskOutputData call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Tasks(Session session, string scope, string table, Filter filter)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter)
            };
            return await sendRequest(session, request, "tasks", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Tasks call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Lineage(Session session, string scope, string table, Filter filter)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter)
            };
            return await sendRequest(session, request, "lineage", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Lineage call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> History(
        Session session,
        string scope,
        string table,
        Filter filter,
        HistoryOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "history", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform History call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Writers(Session session, string scope, string table, Filter filter)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "writers", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Writers call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> DeployOracle(
        Session session,
        string oracleType,
        string targetBlockchain,
        DeployOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["oracleType"] = oracleType,
                ["targetBlockchain"] = targetBlockchain,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "deploy_oracle", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform DeployOracle call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> PostMessage(
        Session session,
        string targetInboxKey,
        string message,
        MessageOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["targetInboxKey"] = targetInboxKey,
                ["options"] = JsonSerializer.Serialize(options),
                ["message"] = message,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "post_message", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform PostMessage call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> PollMessages(Session session, string inboxKey, MessageOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["inboxKey"] = inboxKey
            };
            return await sendRequest(session, request, "poll_message", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform PollMessages call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> DeployFeed(Session session, string image, DeployOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["image"] = image,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "deploy_feed", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform DeployFeed call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> RemoveFeed(Session session, string feedId)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["feedId"] = feedId,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "remove_feed", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform RemoveFeed call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> StartFeed(Session session, string feedId, ComputeOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["feedId"] = feedId,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "start_feed", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform StartFeed call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> StopFeed(Session session, string feedId)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["feedId"] = feedId,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "stop_feed", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform StopFeed call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> CreateUserAccount(
        Session session,
        string publicKey,
        ChainOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["publicKey"] = publicKey,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "create_account", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform CreateUserAccount call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Deploy(Session session, string contractType, ChainOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["contractType"] = contractType,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "deploy", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Deploy call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Call(
        Session session,
        string contractAddress,
        string scope,
        string function,
        byte[] data,
        ChainOptions options
    )
    {
        try
        {
            var encodedData = Base64.Encode(data);
            var iv = SignUtils.GenerateIv();
            var toSign =
                session.GetOrganization()
                + "\n"
                + _apiContext.GetEncodedClientPubKey()
                + "\n"
                + contractAddress
                + "\n"
                + scope
                + "\n"
                + function
                + "\n"
                + encodedData;
            string signature = SignUtils.GenerateSharedKeySignature(
                toSign,
                _apiContext.GetSharedSecret(),
                iv,
                _apiContext.GetSeedHex()
            );
            var request = new Dictionary<string, object>
            {
                ["data"] = Convert.ToBase64String(encodedData),
                ["x-iv"] = SignUtils.ToHexString(iv),
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["function"] = function,
                ["contractAddress"] = contractAddress,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "call", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Call call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Balance(
        Session session,
        string accountAddress,
        string scope,
        string token
    )
    {
        try
        {
            var iv = SignUtils.GenerateIv();
            var toSign =
                session.GetOrganization()
                + "\n"
                + _apiContext.GetEncodedClientPubKey()
                + "\n"
                + accountAddress
                + "\n"
                + scope
                + "\n"
                + token;
            string signature = SignUtils.GenerateSharedKeySignature(
                toSign,
                _apiContext.GetSharedSecret(),
                iv,
                _apiContext.GetSeedHex()
            );
            var request = new Dictionary<string, object>
            {
                ["accountAddress"] = accountAddress,
                ["x-iv"] = SignUtils.ToHexString(iv),
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["token"] = token
            };
            return await sendRequest(session, request, "balance", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Balance call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Transfer(
        Session session,
        string accountAddress,
        string scope,
        string token,
        double amount
    )
    {
        try
        {
            var iv = SignUtils.GenerateIv();
            var toSign =
                session.GetOrganization()
                + "\n"
                + _apiContext.GetEncodedClientPubKey()
                + "\n"
                + accountAddress
                + "\n"
                + scope
                + "\n"
                + token
                + "\n"
                + amount;
            var signature = SignUtils.GenerateSharedKeySignature(
                toSign,
                _apiContext.GetSharedSecret(),
                iv,
                _apiContext.GetSeedHex()
            );
            var request = new Dictionary<string, object>
            {
                ["amount"] = amount.ToString(CultureInfo.InvariantCulture),
                ["accountAddress"] = accountAddress,
                ["x-iv"] = SignUtils.ToHexString(iv),
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["token"] = token
            };
            return await sendRequest(session, request, "transfer", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Transfer call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> UpdateFees(Session session, string scope, string fees)
    {
        try
        {
            var iv = SignUtils.GenerateIv();
            var toSign =
                session.GetOrganization()
                + "\n"
                + _apiContext.GetEncodedClientPubKey()
                + "\n"
                + scope
                + "\n"
                + fees;
            var signature = SignUtils.GenerateSharedKeySignature(
                toSign,
                _apiContext.GetSharedSecret(),
                iv,
                _apiContext.GetSeedHex()
            );
            var request = new Dictionary<string, object>
            {
                ["x-iv"] = SignUtils.ToHexString(iv),
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["token"] = fees
            };
            return await sendRequest(session, request, "update_fees", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform UpdateFees call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ContractState(
        Session session,
        string contractAddress,
        string scope,
        ChainOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["contractAddress"] = contractAddress,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "contract_state", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ContractState call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> BroadcastBlock(
        Session session,
        string scope,
        string block,
        ChainOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["block"] = block,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "broadcast_block", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform BroadcastBlock call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> BroadcastChain(
        Session session,
        string scope,
        List<string> blocks,
        ChainOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["blocks"] = JsonSerializer.Serialize(blocks),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "broadcast_chain", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform BroadcastChain call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> IssueCredentials(
        Session session,
        string issuer,
        string holder,
        Dictionary<string, object> credentials,
        CredentialsOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["credentials"] = JsonSerializer.Serialize(credentials),
                ["organization"] = session.GetOrganization(),
                ["holder"] = holder,
                ["account"] = session.GetAccount(),
                ["issuer"] = issuer
            };
            return await sendRequest(session, request, "issue_credentials", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform IssueCredentials call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> VerifyCredentials(
        Session session,
        Dictionary<string, object> credentials,
        CredentialsOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["credentials"] = JsonSerializer.Serialize(credentials),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "verify_credentials", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform VerifyCredentials call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> CreatePresentation(
        Session session,
        Dictionary<string, object> credentials,
        string subject,
        CredentialsOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["credentials"] = JsonSerializer.Serialize(credentials),
                ["subject"] = subject,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "create_presentation", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform CreatePresentation call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> SignPresentation(
        Session session,
        Dictionary<string, object> presentation,
        string domain,
        string challenge,
        CredentialsOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["presentation"] = JsonSerializer.Serialize(presentation),
                ["organization"] = session.GetOrganization(),
                ["domain"] = domain,
                ["challenge"] = challenge,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "sign_presentation", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform SignPresentation call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> VerifyPresentation(
        Session session,
        Dictionary<string, object> signedPresentation,
        string domain,
        string challenge,
        CredentialsOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["presentation"] = JsonSerializer.Serialize(signedPresentation),
                ["organization"] = session.GetOrganization(),
                ["domain"] = domain,
                ["challenge"] = challenge,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "verify_presentation", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform VerifyPresentation call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Get(Session session, string requestType, string scope, string table)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "null", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Get call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ForwardedRequest(Session session, Dictionary<string, string> msg)
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "forwarded_request",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ForwardedRequest call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> UpdateConfig(
        Session session,
        string path,
        Dictionary<string, object> values
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["path"] = path,
                ["organization"] = session.GetOrganization(),
                ["values"] = JsonSerializer.Serialize(values),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "update_config", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform UpdateConfig call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> CreateUserAccount(
        Session session,
        string targetOrganization,
        string newAccount,
        string publicKey,
        HashSet<string> roles,
        bool isSuperAdmin
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["targetOrganization"] = targetOrganization,
                ["roles"] = JsonSerializer.Serialize(roles),
                ["targetAccount"] = newAccount,
                ["isSuperAdmin"] = (isSuperAdmin ? 1 : 0).ToString(),
                ["publicKey"] = publicKey,
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "create_user_account", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform CreateUserAccount call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ResetConfig(Session session)
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "reset_config",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ResetConfig call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GetScopes(Session session)
    {
        try
        {
            return await sendRequest(session, new Dictionary<string, object>(), "get_scopes", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GetScopes call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GetAccountNotifications(Session session)
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "get_account_notifications",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GetAccountNotifications call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ContractState(Session session, string contractAddress, string scope)
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "reset_config",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ContractState call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> UpdateFee(Session session, string scope, string fees)
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "reset_config",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform UpdateFee call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GetTables(Session session, String scope)
    {
        try
        {
            return await sendRequest(session, new Dictionary<string, object>(), "get_tables", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GetTables call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GetNodeConfig(Session session, String scope)
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "get_node_config",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GetNodeConfig call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Withdraw(Session session, BigInteger amount)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["amount"] = amount.ToString(),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "withdraw", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Withdraw call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> SetThresholdSigPubKey(
        Session session,
        string scope,
        string table,
        ThresholdSigOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["options"] = JsonSerializer.Serialize(options)
            };
            return await sendRequest(session, request, "set_threshold_sig_pub_key", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform SetThresholdSigPubKey call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ReadThresholdSigPubKey(
        Session session,
        string scope,
        string table,
        ThresholdSigOptions options
    )
    {
        try
        {
            return await sendRequest(
                session,
                new Dictionary<string, object>(),
                "read_threshold_sig_pub_key",
                true
            );
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ReadThresholdSigPubKey call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ThresholdSigPubkeyRound1(
        Session session,
        string scope,
        string table,
        string uuid,
        string message,
        ThresholdSigOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["type"] = "threshold_sig_pubkey_round_1",
                ["message"] = message,
                ["uuid"] = uuid,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await sendRequest(session, request, "threshold_sig_pubkey_round_1", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ThresholdSigPubkeyRound1 call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ThresholdSigRound2(
        Session session,
        string scope,
        string table,
        string uuid,
        string hash,
        byte[] scalarK,
        ThresholdSigOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["scalarK"] = new Base58(Base58Alphabet.Bitcoin).Encode(scalarK),
                ["type"] = "threshold_sig_round_2",
                ["uuid"] = uuid,
                ["account"] = session.GetAccount(),
                ["table"] = table,
                ["hash"] = hash
            };
            return await sendRequest(session, request, "threshold_sig_round_2", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ThresholdSigRound2 call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> PeerStatus(Session session, List<string> queuedReplies)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["passive_replies"] = JsonSerializer.Serialize(queuedReplies),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await sendRequest(session, request, "peer_status", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform PeerStatus call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    private async Task<string> Download(Uri uri, int size, Action<byte[]> callback)
    {
        try
        {
            return await sendRequest(null, new Dictionary<string, object>(), "download", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Download call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Withdraw(Session session, string token, BigInteger amount)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["amount"] = amount.ToString()
            };
            return await sendRequest(session, request, "withdraw", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Withdraw call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> BlindSignature(Session session, string blinded)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["blinded"] = blinded
            };
            return await sendRequest(session, request, "blind_signature", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform BlindSignature call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> BlsKey()
    {
        try
        {
            return await sendRequest(null, new Dictionary<string, object>(), "bls_key", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform BlsKey call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> BroadCast(Session session, ConsensusMessage message)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = message.GetScope(),
                ["table"] = message.GetTable()
            };
            return await sendRequest(session, request, "broadcast", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform BroadCast call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Count(
        Session session,
        string scope,
        string table,
        Filter filter,
        ReadOptions options
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter),
                ["options"] = JsonSerializer.Serialize(options)
            };
            return await sendRequest(session, request, "count", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Count call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> CreateAccount(Session session, string pulicKey, ChainOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["publicKey"] = pulicKey
            };
            return await sendRequest(session, request, "create_account", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform CreateAccount call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> EmailAuth(
        string organization,
        string clientPubKey,
        string targetEmail,
        string targetWebUrl
    )
    {
        try
        {
            var request = new Dictionary<string, string>
            {
                ["organization"] = organization,
                ["clientPublicKey"] = clientPubKey,
                ["targetEmail"] = targetEmail,
            };
            string toSign = clientPubKey + "\n" + targetEmail;
            string signature = SignUtils.SignEd25519(toSign, _apiContext.GetEdClientPrivateKey());
            request["signature"] = signature;
            request["x-sig-key"] = new Base58(Base58Alphabet.Bitcoin).Encode(
                _apiContext.GetEdClientPublicKey().GetEncoded()
            );
            if (targetWebUrl != null)
            {
                request["targetWebUrl"] = targetWebUrl;
            }
            string json = JsonSerializer.Serialize(request);
            string encoded = Convert.ToBase64String(Base64.Encode(Encoding.ASCII.GetBytes(json)));
            var args = new Dictionary<string, object>() { ["encodedData"] = encoded };
            return await sendRequest(null, args, "email_auth", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform EmailAuth call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> EnableProduct(
        Session session,
        string did,
        string productType,
        bool active
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["did"] = did,
                ["productType"] = productType,
                ["active"] = active.ToString()
            };
            return await sendRequest(session, request, "enable_product", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform EnableProduct call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> GrantRole(Session session, string account, HashSet<string> roles)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["targetAccount"] = account,
                ["roles"] = JsonSerializer.Serialize(roles)
            };
            return await sendRequest(session, request, "grant_role", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform GrantRole call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> PluginCall(
        Session session,
        string plugin,
        string requestString,
        Dictionary<string, object> args,
        int timeoutSec
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["plugin"] = plugin,
                ["request"] = requestString,
                ["args"] = JsonSerializer.Serialize(args)
            };
            return await sendRequest(session, request, "plugin_call", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform PluginCall call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ProofsLastHash(Session session, string scope, string table)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table
            };
            return await sendRequest(session, request, "proofs_last_hash", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ProofsLastHash call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ProxyEncryptSecret(
        Session session,
        string scope,
        string table,
        ProxyEncryptedData pre
    )
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["pre"] = JsonSerializer.Serialize(pre)
            };
            return await sendRequest(session, request, "proxy_encrypt", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ProxyEncryptSecret call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> ProxyReEncryptSecret(Session session, string scope, string table)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table
            };
            return await sendRequest(session, request, "proxy_reencrypt", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform ProxyReEncryptSecret call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> RsaKey()
    {
        try
        {
            return await sendRequest(null, new Dictionary<string, object>(), "rsa_key", false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform RsaKey call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> splitLearn(Session session, string image, SplitLearnOptions options)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["image"] = image,
                ["options"] = JsonSerializer.Serialize(options)
            };
            return await sendRequest(session, request, "split_learn", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform splitLearn call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> UpdateProofs(Session session, string scope, string table)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table
            };
            return await sendRequest(session, request, "update_proofs", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform UpdateProofs call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> UploadApi(Session session, Dictionary<string, object> parameters)
    {
        try
        {
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["params"] = JsonSerializer.Serialize(parameters)
            };
            return await sendRequest(session, request, "upload_api", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform UploadApi call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> WithdrawAuthorize(Session session, string token, string address)
    {
        try
        {
            string toSign = token + "\n" + address;
            string signature = SignUtils.SignEd25519(toSign, _apiContext.GetEdClientPrivateKey());
            var request = new Dictionary<string, object>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["address"] = address,
                ["signature"] = signature
            };
            return await sendRequest(session, request, "withdraw_auth", true);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform WithdrawAuthorize call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }
}
