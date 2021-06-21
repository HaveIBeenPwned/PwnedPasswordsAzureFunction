using System.Net;
using System.Threading.Tasks;
using Azure.Storage.Queues;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Functions
{
    public class StorageQueue
    {
        private ILogger _log;
        private QueueClient _queueClient;

        public StorageQueue(IConfiguration configuration, ILogger<StorageQueue> log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            var ingestQueueName = configuration["PasswordIngestQueueName"];

            _queueClient = new QueueClient(storageConnectionString, ingestQueueName, new QueueClientOptions
            {
                MessageEncoding = QueueMessageEncoding.Base64
            });
        }

        /// <summary>
        /// Push a append job to the queue
        /// </summary>
        /// <param name="append">The append request to push to the queue</param>
        public async Task PushPassword(PwnedPasswordAppend append)
        {
            var json = JsonConvert.SerializeObject(append);
            await _queueClient.SendMessageAsync(json);
        }
    }
}
