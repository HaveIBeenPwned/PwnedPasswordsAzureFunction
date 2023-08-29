// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.IO.Pipelines;
using System.Text.Json;
using System.Text.Json.Serialization;

using HaveIBeenPwned.PwnedPasswords;

Console.WriteLine("Hello, World!");
Dictionary<string, List<HashEntry>> entries = new ();

foreach (string ingestionFile in Directory.EnumerateFiles($@"**REPLACE WITH INPUT**"))
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

int num = 0;
await Parallel.ForEachAsync(entries, WriteEnties);

async ValueTask WriteEnties(KeyValuePair<string, List<HashEntry>> entry, CancellationToken cancellationToken)
{
    await ParseAndUpdateHashFile(entry.Key, entry.Value, false).ConfigureAwait(false);
    entries.Remove(entry.Key);
    num++;
    if (num % 100 == 0)
    {
        Console.WriteLine($"Done writing {num} files.");
    }
}

static async Task ParseAndUpdateHashFile(string prefix, List<HashEntry> batchEntries, bool writeBinary)
{
    byte[] Newline = "\r\n"u8.ToArray();

    try
    {
        SortedSet<HashEntry> entries = new();

        // Let's read the existing blob into a sorted dictionary so we can write it back in order!
        FileStream file = File.Open($@"**REPLACE WITH OUTPUT**\{prefix}.txt", new FileStreamOptions()
        {
            Access = FileAccess.Read,
            Mode = FileMode.Open,
            Options = FileOptions.Asynchronous | FileOptions.SequentialScan
        });
        var pipeReader = PipeReader.Create(file);
        await foreach (HashEntry entry in HashEntry.ParseTextHashEntries(prefix, pipeReader))
        {
            entries.Add(entry);
        }

        // We now have a sorted dictionary with the hashes for this prefix.
        // Let's add or update the suffixes with the prevalence counts.
        foreach (HashEntry item in batchEntries)
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

        file = File.Open($@"**REPLACE WITH OUTPUT**\{prefix}.{(writeBinary ? "bin" : "txt")}", new FileStreamOptions()
        {
            Access = FileAccess.Write,
            Mode = FileMode.Create,
            Options = FileOptions.Asynchronous
        });
        var pipeWriter = PipeWriter.Create(file);
        int lastI = entries.Count - 1;
        int i = 0;
        foreach (HashEntry item in entries)
        {
            if (writeBinary)
            {
                item.WriteAsBinaryTo(pipeWriter, true);
            }
            else
            {
                item.WriteTextTo(pipeWriter, true);
                if (i++ != lastI)
                {
                    Memory<byte> mem = pipeWriter.GetMemory(2);
                    Newline.CopyTo(mem);
                    pipeWriter.Advance(2);
                }
            }
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
