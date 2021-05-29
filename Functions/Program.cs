using Azure.Storage.Blobs;
using Functions.Services.HttpResponder;
using Functions.Services.Storage;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Reflection;

namespace Functions
{
    public class Program
    {
        public static void Main()
        {
            var host = new HostBuilder()
                .ConfigureFunctionsWorkerDefaults()
                .ConfigureAppConfiguration(builder =>
                {
                    builder.AddUserSecrets(Assembly.GetExecutingAssembly(), true);
                })
                .ConfigureServices(s =>
                {
                    var config = s.BuildServiceProvider().GetService<IConfiguration>();
                    s.AddOptions<StorageOptions>()
                     .Bind(config.GetSection(StorageOptions.ConfigSection))
                     .ValidateDataAnnotations();

                    s.AddSingleton(provider => new BlobServiceClient(config["Storage:ConnectionString"]));
                    s.AddSingleton<IHttpResponderService, DefaultHttpResponderService>();
                    s.AddSingleton<IStorageService, BlobStorageService>();
                })
                .Build();

            host.Run();
        }
    }
}