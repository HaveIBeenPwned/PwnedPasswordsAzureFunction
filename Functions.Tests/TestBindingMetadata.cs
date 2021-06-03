using System;
using Microsoft.Azure.Functions.Worker;

namespace Functions.Tests
{
    // Copied from https://github.com/Azure/azure-functions-dotnet-worker/blob/main/test/DotNetWorkerTests/TestBindingMetadata.cs
    public class TestBindingMetadata : BindingMetadata
    {
        public TestBindingMetadata(string type, BindingDirection direction)
        {
            Type = type;
            Direction = direction;
        }

        public override string Type { get; }

        public override BindingDirection Direction { get; }
    }
}
