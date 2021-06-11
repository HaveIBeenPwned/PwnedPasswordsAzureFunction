using System;
using System.Collections.Generic;

using Microsoft.Azure.Functions.Worker;

using Moq;

namespace Functions.Tests
{
    // Copied from: https://github.com/Azure/azure-functions-dotnet-worker/blob/main/test/DotNetWorkerTests/TestFunctionContext.cs
    internal class TestFunctionContext : FunctionContext
    {
        private readonly FunctionInvocation _invocation;

        public TestFunctionContext() : this(new TestFunctionDefinition(), new TestFunctionInvocation())
        {
        }

        public TestFunctionContext(FunctionDefinition functionDefinition, FunctionInvocation invocation)
        {
            FunctionDefinition = functionDefinition;
            _invocation = invocation;
            BindingContext = new TestBindingContext();
        }

        public override IServiceProvider InstanceServices { get; set; } = Mock.Of<IServiceProvider>();

        public override FunctionDefinition FunctionDefinition { get; }

        public override IDictionary<object, object> Items { get; set; } = new Dictionary<object, object>();

        public override IInvocationFeatures Features { get; } = Mock.Of<IInvocationFeatures>();

        public override string InvocationId => _invocation.Id;

        public override string FunctionId => _invocation.FunctionId;

        public override TraceContext TraceContext => _invocation.TraceContext;

        public override BindingContext BindingContext { get; }
    }

    internal class TestBindingContext : BindingContext
    {
        public override IReadOnlyDictionary<string, object?> BindingData => new Dictionary<string, object?>();
    }
}
