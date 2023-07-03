using System.Globalization;
using System.Numerics;
using Org.BouncyCastle.Utilities.Encoders;
using SimpleBase;

namespace weaveapi;

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

public class WeaveHttpApiClient : IWeaveApiClient
{
    private const string ClientVersion = "v1";
    private const int DownloadBufferSize = 1024 * 1024;
    private readonly JsonSerializerOptions _serializeOptions =
        new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = false };

    private readonly string _apiUrl;
    private readonly HttpClient _httpClient = new();
    private readonly ApiContext _apiContext;

    public WeaveHttpApiClient(HttpClientConfig config)
    {
        _apiUrl = GetApiUrl(config);
        _apiContext = new ApiContext(config);
    }

    public async Task Init()
    {
        var converter = new JsonStringEnumConverter();
        _serializeOptions.Converters.Add(converter);
        var serverPublicKeyResponse = await PublicKey();
        var serverPublicKeyResponseString = serverPublicKeyResponse;
        _apiContext.SetDecodedServerPubKey(serverPublicKeyResponseString);
        _apiContext.ComputeSharedSecret();
    }

    public async Task<string> AuthPost(Uri uri, Dictionary<string, string> request, Session session)
    {
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, uri);

        requestMessage.Content = new StringContent(JsonSerializer.Serialize(request));

        requestMessage.Headers.Add("x-api-key", session.GetApiKey());

        var nonce = session.IncrementNonceAndGetString();
        requestMessage.Headers.Add("x-nonce", nonce);

        var jsonBody = JsonSerializer.Serialize(request);
        if (jsonBody.Length == 0)
        {
            jsonBody = "{}";
        }

        var uriString = uri.ToString();
        var toSign =
            uriString[uriString.LastIndexOf("/", uriString.LastIndexOf("/") - 1)..]
            + "\n"
            + session.GetApiKey()
            + "\n"
            + nonce
            + "\n"
            + jsonBody;
        byte[] signature = SignUtils.HashHmac(session.GetSecret(), toSign);
        string signatureString = Convert.ToBase64String(signature);

        requestMessage.Headers.Add("x-sig", signatureString);

        return await (await _httpClient.SendAsync(requestMessage)).Content
            .ReadAsStringAsync()
            .ConfigureAwait(false);
    }

    private async Task<string> Post(Uri uri, Dictionary<string, string> request)
    {
        var requestMessage = new HttpRequestMessage(HttpMethod.Post, uri);
        requestMessage.Content = new StringContent(JsonSerializer.Serialize(request));
        return await (await _httpClient.SendAsync(requestMessage)).Content
            .ReadAsStringAsync()
            .ConfigureAwait(false);
    }

    public async Task<string> SyncGet(Session session, string requestType, string table)
    {
        var uri = new Uri(_apiUrl + "/" + ClientVersion + "/" + requestType);
        var request = new Dictionary<string, string>();
        if (session.GetAccount() != null)
        {
            request["account"] = session.GetAccount();
        }

        if (table != null)
        {
            request["table"] = table;
        }

        return await AuthPost(uri, request, session);
    }

    private static string GetApiUrl(HttpClientConfig config)
    {
        var protocol = config.IsUseHttps() ? "https" : "http";
        return $"{protocol}://{config.GetHost()}:{config.GetPort()}";
    }

    public async Task<string> PublicKey()
    {
        try
        {
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/public_key");
            HttpResponseMessage message = await _httpClient.GetAsync(uri);
            return await message.Content.ReadAsStringAsync().ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform PublicKey call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<Session> Login(string organization, string account, string scopes)
    {
        try
        {
            var iv = SignUtils.GenerateIv();
            var toSign = organization + "\n" + account + "\n" + scopes;

            var pubSigKey = new Base58(Base58Alphabet.Bitcoin).Encode(
                _apiContext.GetEdClientPublicKey().GetEncoded()
            );
            var contentDictionary = new Dictionary<string, string>
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

            HttpContent content = new StringContent(JsonSerializer.Serialize(contentDictionary));
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/login");
            var sessionResponseMessage = await _httpClient.PostAsync(uri, content);

            var resString = await sessionResponseMessage.Content
                .ReadAsStringAsync()
                .ConfigureAwait(false);
            var dataJson = JsonSerializer.Deserialize<Dictionary<string, object>>(resString)[
                "data"
            ].ToString();
            var sessionResponse = JsonSerializer.Deserialize<Dictionary<string, object>>(dataJson);

            var byteArrayIv = SignUtils.HexStringToByteArray(sessionResponse["x-iv"].ToString());
            var byteArraySecret = SignUtils.HexStringToByteArray(
                sessionResponse["secret"].ToString()
            );
            var decryptedSecret = SignUtils.Decrypt(
                byteArraySecret,
                _apiContext.GetSharedSecret(),
                byteArrayIv,
                _apiContext.GetSeedHex()
            );
            return new Session(sessionResponse, decryptedSecret);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Login call: " + e.ToString());
            return null;
        }
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/create");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table
            };

            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/write");

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

            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = records.Table,
                ["options"] = JsonSerializer.Serialize(writeOptions),
                ["records"] = JsonSerializer.Serialize(records, _serializeOptions)
            };

            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/get_table_definition");
            var request = new Dictionary<string, string> { ["scope"] = scope, ["table"] = table };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/ping");
            return await (await _httpClient.GetAsync(uri)).Content
                .ReadAsStringAsync()
                .ConfigureAwait(false);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/read");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter, _serializeOptions),
                ["options"] = JsonSerializer.Serialize(readOptions, _serializeOptions)
            };

            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/version");
            return await (await _httpClient.GetAsync(uri)).Content
                .ReadAsStringAsync()
                .ConfigureAwait(false);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/sig_key");
            return await (await _httpClient.GetAsync(uri)).Content
                .ReadAsStringAsync()
                .ConfigureAwait(false);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/proxy_login");
            return await Post(uri, new Dictionary<string, string>());
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/logout");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/terms");
            var termsOptions = JsonSerializer.Serialize(options);
            var request = new Dictionary<string, string>
            {
                ["signature"] = SignUtils.SignEd25519(
                    termsOptions,
                    _apiContext.GetEdClientPrivateKey()
                ),
                ["organization"] = session.GetOrganization(),
                ["options"] = termsOptions,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/status");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/drop");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/update_layout");
            var request = new Dictionary<string, string>
            {
                ["layout"] = layout,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/get_sidechain_details");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/delete");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/hashes");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/download_table");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["format"] = format.ToString(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/download_dataset");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["did"] = did
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/publish_dataset");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/run_task");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["did"] = did
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/publish_task");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/subscribe");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/unsubscribe");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["subscriptionId"] = subscriptionId,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/compute");
            var request = new Dictionary<string, string>
            {
                ["image"] = image,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/f_learn");
            var request = new Dictionary<string, string>
            {
                ["image"] = image,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/he_get_inputs");
            var request = new Dictionary<string, string>
            {
                ["args"] = JsonSerializer.Serialize(args),
                ["datasources"] = JsonSerializer.Serialize(datasources),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/he_get_outputs");
            var request = new Dictionary<string, string>
            {
                ["args"] = JsonSerializer.Serialize(args),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["encoded"] = encoded
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/he_encode");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["items"] = JsonSerializer.Serialize(items),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/zk_proof");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Version call: " + e.ToString());
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/zk_data_proof");
            var request = new Dictionary<string, string>
            {
                ["gadget"] = gadget,
                ["organization"] = session.GetOrganization(),
                ["values"] = JsonSerializer.Serialize(values),
                ["options"] = JsonSerializer.Serialize(options),
                ["params"] = gadgetParams,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/mpc");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/mpc_init");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/mpc_proto");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["message"] = message,
                ["account"] = session.GetAccount(),
                ["computationId"] = computationId
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/storage_proof");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["challenge"] = challenge,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/zk_storage_proof");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["challenge"] = challenge,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/merkle_tree");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["salt"] = salt,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/merkle_proof");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table,
                ["hash"] = hash
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/zk_merkle_tree");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/root_hash");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/verify_data_signature");
            var request = new Dictionary<string, string>
            {
                ["data"] = data,
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/get_nodes");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/task_lineage");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["taskId"] = taskId
            };
            return await AuthPost(uri, request, session);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform TaskLineage call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> HashCheckpoint(Session session, Boolean enable)
    {
        try
        {
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/hash_checkpoint");
            var request = new Dictionary<string, string>
            {
                ["enable"] = enable.ToString(),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform HashCheckpoint call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> HashCheckpoint(Session session)
    {
        return await HashCheckpoint(session, false);
    }

    public async Task<string> VerifyTaskLineage(
        Session session,
        Dictionary<string, object> metadata
    )
    {
        try
        {
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/verify_task_lineage");
            var request = new Dictionary<string, string>
            {
                ["metadata"] = JsonSerializer.Serialize(metadata),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform VerifyTaskLineage call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> TaskOutputData(Session session, string taskId, OutputOptions options)
    {
        try
        {
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/task_output_data");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["taskId"] = taskId
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/tasks");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/lineage");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/history");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/writers");
            var request = new Dictionary<string, string>
            {
                ["filter"] = JsonSerializer.Serialize(filter),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/deploy_oracle");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["oracleType"] = oracleType,
                ["targetBlockchain"] = targetBlockchain,
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/deploy_oracle");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["targetInboxKey"] = targetInboxKey,
                ["options"] = JsonSerializer.Serialize(options),
                ["message"] = message,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/deploy_oracle");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount(),
                ["inboxKey"] = inboxKey
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/deploy_feed");
            var request = new Dictionary<string, string>
            {
                ["image"] = image,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/remove_feed");
            var request = new Dictionary<string, string>
            {
                ["feedId"] = feedId,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/start_feed");
            var request = new Dictionary<string, string>
            {
                ["feedId"] = feedId,
                ["organization"] = session.GetOrganization(),
                ["options"] = JsonSerializer.Serialize(options),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/stop_feed");
            var request = new Dictionary<string, string>
            {
                ["feedId"] = feedId,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/create_account");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["publicKey"] = publicKey,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/deploy");
            var request = new Dictionary<string, string>
            {
                ["contractType"] = contractType,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/call");
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
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/balance");
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
            var request = new Dictionary<string, string>
            {
                ["accountAddress"] = accountAddress,
                ["x-iv"] = SignUtils.ToHexString(iv),
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["token"] = token
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/transfer");
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
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/update_fees");
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
            var request = new Dictionary<string, string>
            {
                ["x-iv"] = SignUtils.ToHexString(iv),
                ["signature"] = signature,
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["token"] = fees
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/contract_state");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["contractAddress"] = contractAddress,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/broadcast_block");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["block"] = block,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/broadcast_chain");
            var request = new Dictionary<string, string>
            {
                ["blocks"] = JsonSerializer.Serialize(blocks),
                ["organization"] = session.GetOrganization(),
                ["scope"] = scope,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/issue_credentials");
            var request = new Dictionary<string, string>
            {
                ["credentials"] = JsonSerializer.Serialize(credentials),
                ["organization"] = session.GetOrganization(),
                ["holder"] = holder,
                ["account"] = session.GetAccount(),
                ["issuer"] = issuer
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/verify_credentials");
            var request = new Dictionary<string, string>
            {
                ["credentials"] = JsonSerializer.Serialize(credentials),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/create_presentation");
            var request = new Dictionary<string, string>
            {
                ["credentials"] = JsonSerializer.Serialize(credentials),
                ["subject"] = subject,
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/sign_presentation");
            var request = new Dictionary<string, string>
            {
                ["presentation"] = JsonSerializer.Serialize(presentation),
                ["organization"] = session.GetOrganization(),
                ["domain"] = domain,
                ["challenge"] = challenge,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/verify_presentation");
            var request = new Dictionary<string, string>
            {
                ["presentation"] = JsonSerializer.Serialize(signedPresentation),
                ["organization"] = session.GetOrganization(),
                ["domain"] = domain,
                ["challenge"] = challenge,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/null");
            var request = new Dictionary<string, string>
            {
                ["scope"] = scope,
                ["account"] = session.GetAccount(),
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/forwarded_request");
            return await AuthPost(uri, msg, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/update_config");
            var request = new Dictionary<string, string>
            {
                ["path"] = path,
                ["organization"] = session.GetOrganization(),
                ["values"] = JsonSerializer.Serialize(values),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/create_user_account");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["targetOrganization"] = targetOrganization,
                ["roles"] = JsonSerializer.Serialize(roles),
                ["targetAccount"] = newAccount,
                ["isSuperAdmin"] = (isSuperAdmin ? 1 : 0).ToString(),
                ["publicKey"] = publicKey,
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/reset_config");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/get_scopes");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/get_account_notifications");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/reset_config");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/reset_config");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/get_tables");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/get_node_config");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/withdraw");
            var request = new Dictionary<string, string>
            {
                ["amount"] = amount.ToString(),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/set_threshold_sig_pub_key");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["options"] = JsonSerializer.Serialize(options)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/read_threshold_sig_pub_key");
            return await AuthPost(uri, new Dictionary<string, string>(), session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/threshold_sig_pubkey_round_1");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/threshold_sig_round_2");
            var request = new Dictionary<string, string>
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
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/peer_status");
            var request = new Dictionary<string, string>
            {
                ["passive_replies"] = JsonSerializer.Serialize(queuedReplies),
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount()
            };
            return await AuthPost(uri, request, session);
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
            return await (await _httpClient.GetAsync(uri)).Content
                .ReadAsStringAsync()
                .ConfigureAwait(false);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Download call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> BlindSignature(Session session, string blinded)
    {
        try
        {
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/blind_signature");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["blinded"] = blinded
            };
            return await AuthPost(uri, request, session);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform BlindSignature call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> Withdraw(Session session, string token, BigInteger amount)
    {
        try
        {
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/withdraw");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["amount"] = amount.ToString()
            };
            return await AuthPost(uri, request, session);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform Withdraw call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }

    public async Task<string> BlsKey()
    {
        try
        {
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/bls_key");
            return await (await _httpClient.GetAsync(uri)).Content
                .ReadAsStringAsync()
                .ConfigureAwait(false);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/broadcast");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = message.GetScope(),
                ["table"] = message.GetTable(),
                ["data"] = JsonSerializer.Serialize(message.GetData())
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/count");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["filter"] = JsonSerializer.Serialize(filter),
                ["options"] = JsonSerializer.Serialize(options)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/create_account");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["publicKey"] = pulicKey
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/email_auth");
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
            return await (
                await _httpClient.PostAsync(uri, new StringContent(JsonSerializer.Serialize(args)))
            ).Content
                .ReadAsStringAsync()
                .ConfigureAwait(false);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/enable_product");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["did"] = did,
                ["productType"] = productType,
                ["active"] = active.ToString()
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/grant_role");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["targetAccount"] = account,
                ["roles"] = JsonSerializer.Serialize(roles)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/plugin_call");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["plugin"] = plugin,
                ["request"] = requestString,
                ["args"] = JsonSerializer.Serialize(args)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/proofs_last_hash");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/proxy_encrypt");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table,
                ["pre"] = JsonSerializer.Serialize(pre)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/proxy_reencrypt");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/rsa_key");
            return await Post(uri, new Dictionary<string, string>());
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/split_learn");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["image"] = image,
                ["options"] = JsonSerializer.Serialize(options)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/update_proofs");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["scope"] = scope,
                ["table"] = table
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/upload_api");
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["params"] = JsonSerializer.Serialize(parameters)
            };
            return await AuthPost(uri, request, session);
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
            var uri = new Uri(_apiUrl + "/" + ClientVersion + "/withdraw_auth");
            string toSign = token + "\n" + address;
            string signature = SignUtils.SignEd25519(toSign, _apiContext.GetEdClientPrivateKey());
            var request = new Dictionary<string, string>
            {
                ["organization"] = session.GetOrganization(),
                ["account"] = session.GetAccount(),
                ["address"] = address,
                ["signature"] = signature
            };
            return await AuthPost(uri, request, session);
        }
        catch (Exception e)
        {
            Console.WriteLine("Unable to perform WithdrawAuthorize call: " + e.ToString());
            return "exception: " + e.ToString();
        }
    }
}
