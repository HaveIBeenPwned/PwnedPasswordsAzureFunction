using System;

namespace Functions.Dtos
{
    public record HashFile
    {
        public byte[] Content { get; init; }
        public DateTimeOffset? LastModified { get; init; }
    }
}
