// See https://aka.ms/new-console-template for more information
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO.Pipelines;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

int i = 0;
Channel<Task> channel = Channel.CreateBounded<Task>(new BoundedChannelOptions(16) { AllowSynchronousContinuations = false, SingleWriter = true, SingleReader = true });
Task worker = Task.Run(async () =>
{
    await foreach (var item in channel.Reader.ReadAllAsync().ConfigureAwait(false))
    {
        if (!item.IsCompletedSuccessfully)
        {
            await item.ConfigureAwait(false);
        }
    }
});

await foreach(var item in SplitHashesAsync(@"C:\Users\stefa\Downloads\pwned-passwords-ntlm-ordered-by-hash-v8\pwned-passwords-ntlm-ordered-by-hash-v8.txt", true))
{
    var task = WriteEntries(item.file, item.entries, item.writeBinary);
    await channel.Writer.WriteAsync(task);
}
channel.Writer.TryComplete();
await worker.ConfigureAwait(false);

async IAsyncEnumerable<(string file, List<HashEntry> entries, bool writeBinary)> SplitHashesAsync(string fileName, bool writeBinary)
{
    List<HashEntry> entries = new(1000);
    using FileStream file = File.Open(fileName, new FileStreamOptions() { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.SequentialScan | FileOptions.Asynchronous });
    uint currentPrefix = 0;
    var reader = PipeReader.Create(file);
    await foreach (HashEntry entry in HashEntry.ParseTextHashEntries(reader).ConfigureAwait(false))
    {
        uint prefix = BinaryPrimitives.ReadUInt32BigEndian(entry.Hash.Span) >> 12;
        if (prefix != currentPrefix)
        {
            yield return (GetFileName(writeBinary, entries), entries, writeBinary);
            entries = new List<HashEntry>(1000);
            currentPrefix = prefix;
        }

        entries.Add(entry);
    }

    yield return (GetFileName(writeBinary, entries), entries, true);

    static string GetFileName(bool writeBinary, List<HashEntry> entries) => $@"C:\Users\stefa\source\repos\PwnedPasswordsSplitter\hashes\{Convert.ToHexString(entries[0].Hash.Slice(0, 3).Span)[..5]}.{(writeBinary ? "bin" : "txt")}";
}

async Task WriteEntries(string file, List<HashEntry> entries, bool writeBinary)
{
    using FileStream output = File.Open(file, new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create, Options = FileOptions.Asynchronous, BufferSize = 1024 * 16 });
    var writer = PipeWriter.Create(output);
    for (int i = 0; i < entries.Count; i++)
    {
        using HashEntry entry = entries[i];
        if (writeBinary)
        {
            entry.WriteAsBinaryTo(writer, true);
        }
        else
        {
            entry.WriteTextTo(writer, true);
            if (i != entries.Count - 1)
            {
                Memory<byte> mem = writer.GetMemory(2);
                mem.Span[0] = (byte)'\r';
                mem.Span[1] = (byte)'\n';
                writer.Advance(2);
            }
        }

    }

    await writer.FlushAsync().ConfigureAwait(false);
    await writer.CompleteAsync().ConfigureAwait(false);

    if (i++ % 100 == 0)
    {
        Console.WriteLine($"Wrote file {file}");
    }
}
