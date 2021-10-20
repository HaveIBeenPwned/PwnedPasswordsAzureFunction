
using System;
using System.Collections.Generic;

using HaveIBeenPwned.PwnedPasswords;
using HaveIBeenPwned.PwnedPasswords.Abstractions;
using HaveIBeenPwned.PwnedPasswords.Implementations.Azure;
using HaveIBeenPwned.PwnedPasswords.Implementations.Cloudflare;

using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

[assembly: FunctionsStartup(typeof(Startup))]
namespace HaveIBeenPwned.PwnedPasswords
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            FunctionsHostBuilderContext? context = builder.GetContext();
            builder.Services
                .Configure<BlobStorageOptions>(options =>
                {
                    options.BlobContainerName = context.Configuration["BlobContainerName"];
                    options.ConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
                })
                .Configure<QueueStorageOptions>(options =>
                {
                    options.ConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
                    options.Namespace = context.Configuration["TableNamespace"];
                })
                .Configure<TableStorageOptions>(options =>
                {
                    options.ConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
                    options.Namespace = context.Configuration["TableNamespace"];
                })
                .Configure<CdnStorageOptions>(options =>
                {
                    string _pwnedPasswordsUrl = context.Configuration["PwnedPasswordsBaseUrl"];
                    if (string.IsNullOrEmpty(_pwnedPasswordsUrl))
                    {
                        throw new KeyNotFoundException("\"PwnedPasswordsBaseUrl\" has not been configured.");
                    }
                    options.PwnedPasswordsBaseUrl = _pwnedPasswordsUrl;

                    string apiToken = context.Configuration["CloudflareAPIToken"];
                    if (string.IsNullOrEmpty(apiToken))
                    {
                        throw new KeyNotFoundException("\"CloudflareAPIToken\" has not been configured.");
                    }
                    options.APIToken = apiToken;

                    string zoneId = context.Configuration["CloudflareZoneIdentifier"];
                    if (string.IsNullOrEmpty(zoneId))
                    {
                        throw new KeyNotFoundException("\"CloudflareZoneIdentifier\" has not been configured.");
                    }
                    options.ZoneIdentifier = zoneId;
                })
                .AddSingleton<IFileStorage, BlobStorage>()
                .AddSingleton<IQueueStorage, QueueStorage>()
                .AddSingleton<ICdnStorage, CdnStorage>()
                .AddSingleton<ITableStorage, TableStorage>();

            builder.Services.AddHttpClient<CdnStorage>((serviceProvider, client) =>
            {
                IOptions<CdnStorageOptions> options = serviceProvider.GetRequiredService<IOptions<CdnStorageOptions>>();
                client.BaseAddress = new Uri($"https://api.cloudflare.com/client/v4/zones/{options.Value.ZoneIdentifier}/purge_cache");
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", options.Value.APIToken);
            });
        }
    }
}
