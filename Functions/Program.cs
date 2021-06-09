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
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var host = new HostBuilder()
                .ConfigureFunctionsWorkerDefaults()
                .ConfigureServices((context, services) =>
                {
                    var storageConnectionString = context.Configuration["PwnedPasswordsConnectionString"];

                    services.AddAzureClients(azure => azure.AddBlobServiceClient(storageConnectionString));

                    services.AddSingleton<BlobStorage>();
                })
                .Build();

            host.Run();
        }
    }
}
