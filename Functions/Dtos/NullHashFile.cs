using System;

namespace Functions.Dtos
{
    public record NullHashFile : HashFile
    {
        public NullHashFile()
        {
            Content = Array.Empty<byte>();
            LastModified = null;
        }
    }
}
