using Microsoft.Extensions.Azure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Functions
{
    public class Program
    {
        public static void Main()
        {
            IHost host = new HostBuilder()
                .ConfigureFunctionsWorkerDefaults()
                .ConfigureServices((context, services) =>
                {
                    string storageConnectionString = context.Configuration["PwnedPasswordsConnectionString"];
                    string appInsightsInstrumentationKey = context.Configuration["APPINSIGHTS_INSTRUMENTATIONKEY"];

                    services
                    .AddSingleton<IStorageService, BlobStorage>()
                    .AddApplicationInsightsTelemetryWorkerService(appInsightsInstrumentationKey)
                    .AddAzureClients(azure => azure.AddBlobServiceClient(storageConnectionString));
                })
                .Build();

            host.Run();
        }
    }
}
