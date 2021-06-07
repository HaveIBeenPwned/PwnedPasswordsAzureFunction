
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
                .ConfigureServices(services => services.AddSingleton<BlobStorage>())
                .ConfigureServices(services => services.AddSingleton<TableStorage>())
                .ConfigureServices(services => services.AddSingleton<StorageQueue>())
                .ConfigureServices(services => services.AddSingleton<Cloudflare>())
                .Build();

            host.Run();
        }
    }
}
