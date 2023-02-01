// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

Console.WriteLine("Hello, World!");

Dictionary<string, List<HashEntry>> entries = new ();
Channel<Task> workers = Channel.CreateBounded<Task>(64);

foreach (var ingestionFile in Directory.EnumerateFiles($@"C:\Users\stefa\source\repos\PwnedPasswordsSplitter\ingested\"))
{
    using (Stream stream = File.OpenRead(ingestionFile))
    {
        int count = 0;
        await foreach (PwnedPasswordsIngestionValue? entry in JsonSerializer.DeserializeAsyncEnumerable<PwnedPasswordsIngestionValue>(stream))
        {
            if (entry != null)
            {
                entry.NTLMHash = entry.NTLMHash.ToUpperInvariant();
                string prefix = entry.NTLMHash[..5];
                if (!entries.TryGetValue(prefix, out List<HashEntry>? values))
                {
                    values = new List<HashEntry>();
                    entries[prefix] = values;
                }

                if (HashEntry.TryParseFromText(entry.NTLMHash, entry.Prevalence, out HashEntry hashEntry))
                {
                    values.Add(hashEntry);
                }

                count++;
            }
        }

        Console.WriteLine($"Read {count} entries from {ingestionFile}.");
    }
}

var task = Task.Run(async () =>
{
    DateTimeOffset lastRun = DateTimeOffset.UtcNow;
    int num = 0;
    await foreach (var task in workers.Reader.ReadAllAsync())
    {
        await task;
        num++;
        if ((DateTimeOffset.UtcNow - lastRun) > TimeSpan.FromSeconds(5))
        {
            Console.WriteLine($"Done writing {num} files.");
            lastRun = DateTimeOffset.UtcNow;
        }
    }
});

foreach (var entry in entries)
{
    await workers.Writer.WriteAsync(ParseAndUpdateHashFile(entry.Key, entry.Value));
}
workers.Writer.TryComplete();
await task;

async Task ParseAndUpdateHashFile(string prefix, List<HashEntry> batchEntries)
{
    try
    {
        SortedSet<HashEntry> entries = new();

        // Let's read the existing blob into a sorted dictionary so we can write it back in order!
        var file = File.Open($@"C:\Users\stefa\source\repos\PwnedPasswordsSplitter\binhashes\{prefix}.bin", new FileStreamOptions()
        {
            Access = FileAccess.ReadWrite,
            Mode = FileMode.Open,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan
        });
        var pipeReader = PipeReader.Create(file);
        await foreach (var entry in HashEntry.ParseBinaryHashEntries(prefix, 16, pipeReader))
        {
            entries.Add(entry);
        }

        // We now have a sorted dictionary with the hashes for this prefix.
        // Let's add or update the suffixes with the prevalence counts.
        foreach (var item in batchEntries)
        {
            if (entries.TryGetValue(item, out HashEntry value))
            {
                value.Prevalence += item.Prevalence;
            }
            else
            {
                entries.Add(item);
            }
        }

        file.Dispose();

        file = File.Open($@"C:\Users\stefa\source\repos\PwnedPasswordsSplitter\binhashespatched\{prefix}.bin", new FileStreamOptions()
        {
            Access = FileAccess.Write,
            Mode = FileMode.Create,
            Options = FileOptions.Asynchronous
        });
        var pipeWriter = PipeWriter.Create(file);

        foreach (var item in entries)
        {
            item.WriteAsBinaryTo(pipeWriter, true);
        }

        await pipeWriter.CompleteAsync();
        await pipeWriter.FlushAsync();
    }
    catch(Exception ex)
    {
        Console.WriteLine(ex.ToString());
    }
}

public class PwnedPasswordsIngestionValue
{
    [JsonPropertyName("sha1")]
    public string SHA1Hash { get; set; } = "";
    [JsonPropertyName("ntlm")]
    public string NTLMHash { get; set; } = "";
    [JsonPropertyName("num")]
    public int Prevalence { get; set; }
}
