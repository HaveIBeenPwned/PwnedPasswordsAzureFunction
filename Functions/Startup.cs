
using HaveIBeenPwned.PwnedPasswords;

using Microsoft.Azure.Functions.Extensions.DependencyInjection;
using Microsoft.Extensions.Azure;
using Microsoft.Extensions.DependencyInjection;

[assembly: FunctionsStartup(typeof(Startup))]
namespace HaveIBeenPwned.PwnedPasswords
{
    public class Startup : FunctionsStartup
    {
        public override void Configure(IFunctionsHostBuilder builder)
        {
            FunctionsHostBuilderContext? context = builder.GetContext();
            builder.Services
                .Configure<BlobStorageOptions>(options => options.BlobContainerName = context.Configuration["BlobContainerName"])
                .AddSingleton<IStorageService, BlobStorage>()
                .AddSingleton<TableStorage>()
                .AddSingleton<StorageQueue>()
                .AddSingleton<Cloudflare>()
                .AddAzureClients(azure => azure.AddBlobServiceClient(context.Configuration["PwnedPasswordsConnectionString"]));
        }
    }
}
