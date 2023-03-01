// Copyright (c) .NET Foundation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.

using HaveIBeenPwned.PwnedPasswords.Implementations.Azure;
using HaveIBeenPwned.PwnedPasswords.Implementations.Cloudflare;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Azure;

namespace HaveIBeenPwned.PwnedPasswords
{
    class Program
    {
        public const int Parallelism = 4;

        static async Task Main(string[] args)
        {
            string connectionString = "";
            var host = new HostBuilder()
                .ConfigureFunctionsWorkerDefaults((context, builder) =>
                {
                    connectionString = context.Configuration["PwnedPasswordsConnectionString"];
                    builder
                        .AddApplicationInsights()
                        .AddApplicationInsightsLogger();
                })
                .ConfigureServices(s =>
                {
                    s.AddOptions<BlobStorageOptions>().Configure<IConfiguration>((options, configuration) =>
                    {
                        options.BlobContainerName = configuration["BlobContainerName"];
                        options.ConnectionString = configuration["PwnedPasswordsConnectionString"];
                    });
                    s.AddOptions<QueueStorageOptions>().Configure<IConfiguration>((options, configuration) =>
                    {
                        options.ConnectionString = configuration["PwnedPasswordsConnectionString"];
                        options.Namespace = configuration["TableNamespace"];
                    });
                    s.AddOptions<TableStorageOptions>().Configure<IConfiguration>((options, configuration) =>
                    {
                        options.ConnectionString = configuration["PwnedPasswordsConnectionString"];
                        options.Namespace = configuration["TableNamespace"];
                    });
                    s.AddOptions<CdnStorageOptions>().Configure<IConfiguration>((options, configuration) =>
                    {
                        string _pwnedPasswordsUrl = configuration["PwnedPasswordsBaseUrl"];
                        if (string.IsNullOrEmpty(_pwnedPasswordsUrl))
                        {
                            throw new KeyNotFoundException("\"PwnedPasswordsBaseUrl\" has not been configured.");
                        }
                        options.PwnedPasswordsBaseUrl = _pwnedPasswordsUrl;

                        string apiToken = configuration["CloudflareAPIToken"];
                        if (string.IsNullOrEmpty(apiToken))
                        {
                            throw new KeyNotFoundException("\"CloudflareAPIToken\" has not been configured.");
                        }
                        options.APIToken = apiToken;

                        string zoneId = configuration["CloudflareZoneIdentifier"];
                        if (string.IsNullOrEmpty(zoneId))
                        {
                            throw new KeyNotFoundException("\"CloudflareZoneIdentifier\" has not been configured.");
                        }
                        options.ZoneIdentifier = zoneId;
                    });
                    s.AddSingleton<IFileStorage, BlobStorage>()
                        .AddSingleton<IQueueStorage, QueueStorage>()
                        .AddSingleton<ICdnStorage, CdnStorage>()
                        .AddSingleton<ITableStorage, TableStorage>();

                    s.AddHttpClient();
                    s.AddAzureClients(azureBuilder =>
                    {
                        azureBuilder.AddTableServiceClient(connectionString);
                        azureBuilder.AddBlobServiceClient(connectionString);
                        azureBuilder.AddQueueServiceClient(connectionString).ConfigureOptions(options =>
                        {
                            options.MessageEncoding = QueueMessageEncoding.Base64;
                        });
                    });
                })
                .Build();

            await host.RunAsync();
        }
    }
}
