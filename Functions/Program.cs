using HaveIBeenPwned.PwnedPasswords.Implementations.Azure;
using HaveIBeenPwned.PwnedPasswords.Implementations.Cloudflare;

using Microsoft.Extensions.Azure;
using Microsoft.Extensions.Hosting;
using Microsoft.IO;

var streamManager = new RecyclableMemoryStreamManager();

IHost host = new HostBuilder()
  .ConfigureFunctionsWebApplication()
  .ConfigureServices((context, services) =>
  {
      services.AddApplicationInsightsTelemetryWorkerService();
      services.ConfigureFunctionsApplicationInsights();
      services.Configure<BlobStorageOptions>((options) =>
      {
          options.BlobContainerName = context.Configuration["BlobContainerName"];
          options.ConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
      });
      services.Configure<QueueStorageOptions>((options) =>
      {
          options.ConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
          options.Namespace = context.Configuration["TableNamespace"];
      });
      services.Configure<TableStorageOptions>((options) =>
      {
          options.ConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
          options.Namespace = context.Configuration["TableNamespace"];
      });
      services.Configure<CdnStorageOptions>((options) =>
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
      });
      services.AddSingleton<IFileStorage, BlobStorage>()
          .AddSingleton<IQueueStorage, QueueStorage>()
          .AddSingleton<ICdnStorage, CdnStorage>()
          .AddSingleton<ITableStorage, TableStorage>();

      services.AddHttpClient();
      services.AddAzureClients(azureBuilder =>
      {
          string connectionString = context.Configuration["PwnedPasswordsConnectionString"];
          azureBuilder.AddTableServiceClient(connectionString);
          azureBuilder.AddBlobServiceClient(connectionString);
          azureBuilder.AddQueueServiceClient(connectionString).ConfigureOptions(options =>
          {
              options.MessageEncoding = QueueMessageEncoding.Base64;
          });
      });
  })
  .ConfigureLogging(options =>
  {

  })
  .Build();

await host.RunAsync();
