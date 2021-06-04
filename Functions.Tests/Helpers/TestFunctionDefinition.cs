using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using Microsoft.Azure.Functions.Worker;

namespace Functions.Tests
{
    // Copied from: https://github.com/Azure/azure-functions-dotnet-worker/blob/main/test/DotNetWorkerTests/TestFunctionDefinition.cs
    public class TestFunctionDefinition : FunctionDefinition
    {
        public static readonly string DefaultPathToAssembly = typeof(TestFunctionDefinition).Assembly.Location;
        public static readonly string DefaultEntrypPoint = $"{nameof(TestFunctionDefinition)}.{nameof(DefaultEntrypPoint)}";
        public static readonly string DefaultId = "TestId";
        public static readonly string DefaultName = "TestName";

        public TestFunctionDefinition(string functionId = null, IDictionary<string, BindingMetadata> inputBindings = null, IDictionary<string, BindingMetadata> outputBindings = null, IEnumerable<FunctionParameter> parameters = null)
        {
            if (functionId is not null)
            {
                Id = functionId;
            }

            Parameters = parameters == null ? ImmutableArray<FunctionParameter>.Empty : parameters.ToImmutableArray();
            InputBindings = inputBindings == null ? ImmutableDictionary<string, BindingMetadata>.Empty : inputBindings.ToImmutableDictionary();
            OutputBindings = outputBindings == null ? ImmutableDictionary<string, BindingMetadata>.Empty : outputBindings.ToImmutableDictionary();
        }

        public override ImmutableArray<FunctionParameter> Parameters { get; }

        public override string PathToAssembly { get; } = DefaultPathToAssembly;

        public override string EntryPoint { get; } = DefaultEntrypPoint;

        public override string Id { get; } = DefaultId;

        public override string Name { get; } = DefaultName;

        public override IImmutableDictionary<string, BindingMetadata> InputBindings { get; }

        public override IImmutableDictionary<string, BindingMetadata> OutputBindings { get; }

        /// <summary>
        /// Generates a pre-made <see cref="FunctionDefinition"/> for testing. Always includes a single trigger named "TestTrigger".
        /// </summary>
        /// <param name="inputBindingCount">The number of input bindings to generate. Names will be of the format "TestInput0", "TestInput1", etc.</param>
        /// <param name="outputBindingCount">The number of output bindings to generate. Names will be of the format "TestOutput0", "TestOutput1", etc.</param>
        /// <param name="paramTypes">A list of types that will be used to generate the <see cref="Parameters"/>. Names will be of the format "Parameter0", "Parameter1", etc.</param>
        /// <returns>The generated <see cref="FunctionDefinition"/>.</returns>
        public static FunctionDefinition Generate(int inputBindingCount = 0, int outputBindingCount = 0, params Type[] paramTypes)
        {
            var inputs = new Dictionary<string, BindingMetadata>();
            var outputs = new Dictionary<string, BindingMetadata>();
            var parameters = new List<FunctionParameter>();

            // Always provide a trigger
            inputs.Add($"triggerName", new TestBindingMetadata("TestTrigger", BindingDirection.In));

            for (int i = 0; i < inputBindingCount; i++)
            {
                inputs.Add($"inputName{i}", new TestBindingMetadata($"TestInput{i}", BindingDirection.In));
            }

            for (int i = 0; i < outputBindingCount; i++)
            {
                outputs.Add($"outputName{i}", new TestBindingMetadata($"TestOutput{i}", BindingDirection.Out));
            }

            for (int i = 0; i < paramTypes.Length; i++)
            {
                var properties = new Dictionary<string, object>
                {
                    {"TestPropertyKey", "TestPropertyValue" }
                };

                parameters.Add(new FunctionParameter($"Parameter{i}", paramTypes[i], properties.ToImmutableDictionary()));
            }

            return new TestFunctionDefinition(inputBindings: inputs, outputBindings: outputs, parameters: parameters);
        }

        private void DefaultEntryPoint()
        {
        }
    }
}