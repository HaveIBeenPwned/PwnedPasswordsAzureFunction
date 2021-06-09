using System;
using System.Collections.Generic;
using Microsoft.Azure.Functions.Worker;

namespace Functions.Tests
{
    // Copied from: https://github.com/Azure/azure-functions-dotnet-worker/blob/main/test/DotNetWorkerTests/TestFunctionContext.cs
    internal class TestFunctionContext : FunctionContext, IDisposable
    {
        private readonly FunctionInvocation _invocation;

        public TestFunctionContext()
            : this(new TestFunctionDefinition(), new TestFunctionInvocation())
        {
        }

        public TestFunctionContext(FunctionDefinition functionDefinition, FunctionInvocation invocation)
        {
            FunctionDefinition = functionDefinition;
            _invocation = invocation;

            BindingContext = new TestBindingContext(this);
        }

        public bool IsDisposed { get; private set; }

        public override IServiceProvider InstanceServices { get; set; }

        public override FunctionDefinition FunctionDefinition { get; }

        public override IDictionary<object, object> Items { get; set; }

        public override IInvocationFeatures Features { get; }

        public override string InvocationId => _invocation.Id;

        public override string FunctionId => _invocation.FunctionId;

        public override TraceContext TraceContext => _invocation.TraceContext;

        public override BindingContext BindingContext { get; }

        public void Dispose()
        {
            IsDisposed = true;
        }
    }

    internal class TestBindingContext : BindingContext
    {
        private readonly FunctionContext _functionContext;

        public TestBindingContext(FunctionContext functionContext)
        {
            _functionContext = functionContext ?? throw new ArgumentNullException(nameof(functionContext));
        }

        public override IReadOnlyDictionary<string, object?> BindingData => null;
    }
}
