using System.Collections.Generic;

using Azure.Storage.Blobs;
using Azure.Storage.Queues;

using HaveIBeenPwned.PwnedPasswords;
using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Implementations.Azure;
using HaveIBeenPwned.PwnedPasswords.Implementations.Cloudflare;

using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

[assembly: FunctionsStartup(typeof(Startup))]
namespace HaveIBeenPwned.PwnedPasswords
{

    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            FunctionsHostBuilderContext? context = builder.GetContext();
            builder.Services.AddOptions<BlobStorageOptions>().Configure<IConfiguration>((options, configuration) =>
                {
                    options.BlobContainerName = configuration["BlobContainerName"];
                    options.ConnectionString = configuration["PwnedPasswordsConnectionString"];
                });
            builder.Services.AddOptions<QueueStorageOptions>().Configure<IConfiguration>((options, configuration) =>
                {
                    options.ConnectionString = configuration["PwnedPasswordsConnectionString"];
                    options.Namespace = configuration["TableNamespace"];
                });
            builder.Services.AddOptions<TableStorageOptions>().Configure<IConfiguration>((options, configuration) =>
                {
                    options.ConnectionString = configuration["PwnedPasswordsConnectionString"];
                    options.Namespace = configuration["TableNamespace"];
                });
            builder.Services.AddOptions<CdnStorageOptions>().Configure<IConfiguration>((options, configuration) =>
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
            builder.Services.AddSingleton<IFileStorage, BlobStorage>()
                .AddSingleton<IQueueStorage, QueueStorage>()
                .AddSingleton<ICdnStorage, CdnStorage>()
                .AddSingleton<ITableStorage, TableStorage>();

            builder.Services.AddHttpClient();
            builder.Services.AddAzureClients(azureBuilder =>
            {
                string connectionString = context.Configuration["PwnedPasswordsConnectionString"];
                azureBuilder.AddTableServiceClient(connectionString);
                azureBuilder.AddBlobServiceClient(connectionString);
                azureBuilder.AddQueueServiceClient(connectionString).ConfigureOptions(options =>
                {
                    options.MessageEncoding = QueueMessageEncoding.Base64;
                });
            });
        }
    }
}
