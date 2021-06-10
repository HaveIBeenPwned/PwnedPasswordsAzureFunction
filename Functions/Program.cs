using System.Net;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Functions
{
    public class Program
    {
        public static void Main()
        {
            var host = new HostBuilder()
                .ConfigureFunctionsWorkerDefaults()
                .ConfigureServices((context, services) =>
                {
                    var storageConnectionString = context.Configuration["PwnedPasswordsConnectionString"];

                    services
                    .AddSingleton<BlobStorage>()
                    .AddAzureClients(azure => azure.AddBlobServiceClient(storageConnectionString));
                })
                .Build();

            host.Run();
        }
    }
}
