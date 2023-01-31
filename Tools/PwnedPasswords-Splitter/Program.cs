// See https://aka.ms/new-console-template for more information
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

ConcurrentStack<StringBuilder> stringBuilders = new ConcurrentStack<StringBuilder>();
Channel<(string, List<HashEntry>)> fileWriters = Channel.CreateBounded<(string, List<HashEntry>)>(new BoundedChannelOptions(64) { AllowSynchronousContinuations = false, SingleReader = true, SingleWriter = true });
using var file = File.Open(@"C:\Users\stefa\Downloads\pwned-passwords-ntlm-ordered-by-hash-v8\pwned-passwords-ntlm-ordered-by-hash-v8.txt", new FileStreamOptions() { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.SequentialScan | FileOptions.Asynchronous });
byte[] currentPrefix = new byte[3];
List<HashEntry> entries = new List<HashEntry>();
Memory<byte> prefix = new byte[3];
int i = 0;
List<Task> workers = new List<Task>();
for(int n = 0; n < 16; n++)
{
    workers.Add(Task.Run(async () =>
    {
        await foreach ((string File, List<HashEntry> Entries) item in fileWriters.Reader.ReadAllAsync())
        {
            await WriteBinaryEntries(item.File, item.Entries);
        }
    }));
}


await foreach (var entry in HashEntry.ParseHashEntries(PipeReader.Create(file)))
{
    entry.Hash[..3].CopyTo(prefix);
    prefix.Span[2] = (byte)(prefix.Span[2] & 0xF0);
    if (!prefix.Span.SequenceEqual(currentPrefix))
    {
        await fileWriters.Writer.WriteAsync(($@"C:\Users\stefa\source\repos\PwnedPasswordsSplitter\binhashes\{Convert.ToHexString(currentPrefix)[..5]}.bin", entries));
        entries = new List<HashEntry>(1000);
        prefix.CopyTo(currentPrefix);
    }

    entries.Add(entry);
}

fileWriters.Writer.TryComplete();
await Task.WhenAll(workers);

async Task WriteEntries(string file, List<HashEntry> entries)
{
    if(!stringBuilders.TryPop(out StringBuilder? stringBuilder))
    {
        stringBuilder = new StringBuilder();
    }

    using var fileWriter = File.Open(file, new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create, Options = FileOptions.Asynchronous });
    for (int i = 0; i < entries.Count; i++)
    {
        using HashEntry entry = entries[i];
        if (i == entries.Count - 1)
        {
            stringBuilder.Append($"{Hash.ConvertToHex(entry.Hash.Span)[5..]}:{entry.Prevalence}");
        }
        else
        {
            stringBuilder.Append($"{Hash.ConvertToHex(entry.Hash.Span)[5..]}:{entry.Prevalence}\r\n");
        }
    }

    await fileWriter.WriteAsync(Encoding.UTF8.GetBytes(stringBuilder.ToString()));
    await fileWriter.FlushAsync().ConfigureAwait(false);

    if (i++ % 100 == 0)
    {
        Console.WriteLine($"Wrote file {file}");
    }

    stringBuilder.Clear();
    stringBuilders.Push(stringBuilder);
}

async Task WriteBinaryEntries(string file, List<HashEntry> entries)
{
    using var fileWriter = File.Open(file, new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create, Options = FileOptions.Asynchronous });
    PipeWriter writer = PipeWriter.Create(fileWriter);
    for (int i = 0; i < entries.Count; i++)
    {
        using HashEntry entry = entries[i];
        entry.WriteTo(writer, true);
    }

    writer.Complete();
    await writer.FlushAsync();

    if (i++ % 100 == 0)
    {
        Console.WriteLine($"Wrote file {file}");
    }
}
