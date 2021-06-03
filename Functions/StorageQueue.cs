using System.Net;
using System.Threading.Tasks;
using Microsoft.Azure.Storage.Queue;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace Functions
{
    public class StorageQueue
    {
        private ILogger _log;
        private CloudQueue _queue;

        public StorageQueue(IConfiguration configuration, ILogger log)
        {
            _log = log;
            ServicePointManager.UseNagleAlgorithm = false;
            ServicePointManager.Expect100Continue = false;
            ServicePointManager.DefaultConnectionLimit = 100;

            var storageConnectionString = configuration["PwnedPasswordsConnectionString"];
            var ingestQueueName = configuration["PasswordIngestQueueName"];

            var storageAccount = Microsoft.Azure.Storage.CloudStorageAccount.Parse(storageConnectionString);
            var queueClient = storageAccount.CreateCloudQueueClient();
            _queue = queueClient.GetQueueReference(ingestQueueName);
        }

        /// <summary>
        /// Push a append job to the queue
        /// </summary>
        /// <param name="append">The append request to push to the queue</param>
        public async Task PushPassword(PwnedPasswordAppend append)
        {
            var json = JsonConvert.SerializeObject(append);
            CloudQueueMessage message = new CloudQueueMessage(json);
            await _queue.AddMessageAsync(message);
        }
    }
}
