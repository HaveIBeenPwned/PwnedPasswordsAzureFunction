// See https://aka.ms/new-console-template for more information
using System.Buffers.Binary;
using System.IO.Pipelines;

using HaveIBeenPwned.PwnedPasswords;

int i = 0;
byte[] Newline = "\r\n"u8.ToArray();

IAsyncEnumerable<(string file, List<HashEntry> entries, bool writeBinary)> asyncEnumerable = SplitHashesAsync(@"C:\Users\stefa\Downloads\pwned-passwords-ntlm-ordered-by-hash-v8\pwned-passwords-ntlm-ordered-by-hash-v8.txt", false);
await Parallel.ForEachAsync(asyncEnumerable, WriteEntries).ConfigureAwait(false);

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

async ValueTask WriteEntries((string file, List<HashEntry> entries, bool writeBinary) item, CancellationToken cancellationToken)
{
    using FileStream output = File.Open(item.file, new FileStreamOptions() { Access = FileAccess.Write, Mode = FileMode.Create, Options = FileOptions.Asynchronous, BufferSize = 1024 * 64 });
    var writer = PipeWriter.Create(output, new StreamPipeWriterOptions(minimumBufferSize: 64 * 1024));
    int lastI = item.entries.Count - 1;
    for (int i = 0; i < item.entries.Count; i++)
    {
        using HashEntry entry = item.entries[i];
        if (item.writeBinary)
        {
            entry.WriteAsBinaryTo(writer, true);
        }
        else
        {
            entry.WriteTextTo(writer, true);
            if (i != lastI)
            {
                Memory<byte> mem = writer.GetMemory(2);
                Newline.CopyTo(mem);
                writer.Advance(2);
            }
        }
    }

    ValueTask<FlushResult> flushTask = writer.FlushAsync(cancellationToken);
    if(!flushTask.IsCompletedSuccessfully)
    {
        await flushTask.ConfigureAwait(false);
    }
    await writer.CompleteAsync().ConfigureAwait(false);

    if (i++ % 100 == 0)
    {
        Console.WriteLine($"Wrote file {item.file}");
    }
}
