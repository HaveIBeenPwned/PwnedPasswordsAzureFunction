using System.ComponentModel.DataAnnotations;

namespace Functions.Services.Storage
{
    public class StorageOptions
    {
        [RegularExpression(@"^[a-z]+$", ErrorMessage = "Blob container name must be lower case")]
        public string BlobContainerName { get; set; }

        public static string ConfigSection => "Storage";
    }
}