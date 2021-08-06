using Functions;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using IHost host = new HostBuilder()
    .ConfigureFunctionsWorkerDefaults()
    .ConfigureServices((context, services) =>
    {
        var appInsightsInstrumentationKey = context.Configuration["APPINSIGHTS_INSTRUMENTATIONKEY"];
        var storageConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
        var storageContainerName = context.Configuration["BlobContainerName"];

        services.Configure<BlobStorageOptions>(options => options.BlobContainerName = storageContainerName);

        services.AddAzureClients(azure => azure.AddBlobServiceClient(storageConnectionString));

        services.AddSingleton<IStorageService, BlobStorage>();

        services
            .Configure<BlobStorageOptions>(options => options.BlobContainerName = storageContainerName)
            .AddSingleton<IStorageService, BlobStorage>()
            .AddApplicationInsightsTelemetryWorkerService(appInsightsInstrumentationKey)
            .AddAzureClients(azure => azure.AddBlobServiceClient(storageConnectionString));
    })
    .Build();

await host.RunAsync();
