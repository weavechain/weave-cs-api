## Weavechain C# API

[https://weavechain.com](https://weavechain.com): Layer-0 For Data

#### How to install
```shell
dotnet add package weave-cs-api
```

#### Data read sample

```cs
namespace weaveapi;

public abstract class Main 
{
    private static async Task Main()
    {
        var keyPair = SignUtils.GenerateKeys();
        var pub = keyPair[0];
        var pvk = keyPair[1];
        Console.WriteLine("Public key:  " + pub);
        Console.WriteLine("Private key: " + pvk);

        var seed = "92f30f0b6be2732cb817c19839b0940c";
        var host = "public.weavechain.com";
        var port = "443";
        var isHttps = true;
        HttpClientConfig config = new(host, port, pub, pvk, isHttps, seed);

        NodeApi api = new(config);
        await api.Init();

        var organization = "weavedemo";
        var scope = "shared";
        var table = "directory";
        var session = await api.Login(organization, pub, scope);

        var readRes = await api.Read(session, scope, table, Filter.NONE, ReadOptions.Default);
        Console.WriteLine(readRes);
    }
}
```

#### Docs

[https://docs.weavechain.com](https://docs.weavechain.com)