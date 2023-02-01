// See https://aka.ms/new-console-template for more information
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;
using System.Threading.Channels;

using HaveIBeenPwned.PwnedPasswords;

Channel<(string, List<HashEntry>)> fileWriters = Channel.CreateBounded<(string, List<HashEntry>)>(new BoundedChannelOptions(64) { AllowSynchronousContinuations = false, SingleReader = true, SingleWriter = true });
using var file = File.Open(@"C:\Users\stefa\Downloads\pwned-passwords-ntlm-ordered-by-hash-v8\pwned-passwords-ntlm-ordered-by-hash-v8.txt", new FileStreamOptions() { Access = FileAccess.Read, Mode = FileMode.Open, Options = FileOptions.SequentialScan | FileOptions.Asynchronous });
List<HashEntry> entries = new List<HashEntry>(1000);
uint currentPrefix = 0;
int i = 0;
List<Task> workers = new List<Task>();
for(int n = 0; n < 16; n++)
{
    workers.Add(Task.Run(async () =>
    {
        await foreach ((string File, List<HashEntry> Entries) item in fileWriters.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            await WriteEntries(item.File, item.Entries).ConfigureAwait(false);
        }
    }));
}
var pipe = new Pipe();
_ = file.CopyToAsync(pipe.Writer);

await foreach (var entry in HashEntry.ParseTextHashEntries(16, pipe.Reader).ConfigureAwait(false))
{
    uint prefix = (BinaryPrimitives.ReadUInt32BigEndian(entry.Hash.Span) >> 12);
    if (prefix != currentPrefix)
    {
        await fileWriters.Writer.WriteAsync(($@"C:\Users\stefa\source\repos\PwnedPasswordsSplitter\hashes\{Convert.ToHexString(entries[0].Hash.Slice(0, 3).Span)[..5]}.txt", entries)).ConfigureAwait(false); ;
        entries = new List<HashEntry>(1000);
        currentPrefix = prefix;
    }

    entries.Add(entry);
}

await fileWriters.Writer.WriteAsync(($@"C:\Users\stefa\source\repos\PwnedPasswordsSplitter\hashes\{Convert.ToHexString(entries[0].Hash.Slice(0,3).Span)[..5]}.txt", entries)).ConfigureAwait(false);
fileWriters.Writer.TryComplete();
await Task.WhenAll(workers).ConfigureAwait(false);

async Task WriteEntries(string file, List<HashEntry> entries)
{
    var pipe = new Pipe();
    using var fileWriter = File.Open(file, new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create, Options = FileOptions.Asynchronous, BufferSize = 1024 * 16 });
    var writeTask = pipe.Reader.CopyToAsync(fileWriter);
    var pipeWriter = pipe.Writer;
    for (int i = 0; i < entries.Count; i++)
    {
        using HashEntry entry = entries[i];
        entry.WriteTextTo(pipeWriter, true);
        if (i != entries.Count - 1)
        {
            var mem = pipeWriter.GetMemory(2);
            mem.Span[0] = (byte)'\r';
            mem.Span[1] = (byte)'\n';
            pipeWriter.Advance(2);
        }

        await pipeWriter.FlushAsync().ConfigureAwait(false); ;
    }

    await pipeWriter.CompleteAsync().ConfigureAwait(false); ;
    await writeTask.ConfigureAwait(false);

    if (i++ % 100 == 0)
    {
        Console.WriteLine($"Wrote file {file}");
    }
}

async Task WriteBinaryEntries(string file, List<HashEntry> entries)
{
    using var fileWriter = File.Open(file, new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create, Options = FileOptions.Asynchronous });
    PipeWriter writer = PipeWriter.Create(fileWriter);
    for (int i = 0; i < entries.Count; i++)
    {
        using HashEntry entry = entries[i];
        entry.WriteAsBinaryTo(writer, true);
    }

    writer.Complete();
    await writer.FlushAsync().ConfigureAwait(false);

    if (i++ % 100 == 0)
    {
        Console.WriteLine($"Wrote file {file}");
    }
}
