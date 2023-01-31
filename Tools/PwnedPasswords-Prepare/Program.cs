using System.Text.Json;
using HaveIBeenPwned.PwnedPasswords;

if (args.Length != 2)
{
    throw new ArgumentException("This command requires two arguments.");
}

if (!File.Exists(args[0]))
{
    throw new ArgumentException($"File {args[0]} does not exist.");
}

if (File.Exists(args[1]))
{
    Console.WriteLine($"File {args[1]} already exists. It will be overwritten!");
}

var ntlmName = JsonEncodedText.Encode("ntlm");
var sha1Name = JsonEncodedText.Encode("sha1");
var numName = JsonEncodedText.Encode("num");

using FileStream input = File.OpenRead(args[0]);
using var inputReader = new StreamReader(input);
using FileStream output = File.Create(args[1]);
using var outputWriter = new Utf8JsonWriter(output);

outputWriter.WriteStartArray();
int numPasswords = 0;
while (!inputReader.EndOfStream)
{
    if (outputWriter.BytesPending > 16 * 1024)
    {
        await outputWriter.FlushAsync().ConfigureAwait(false);
    }

    string? line = await inputReader.ReadLineAsync().ConfigureAwait(false);
    if (line != null)
    {
        if (line.LastIndexOf(":") <= 0 || !int.TryParse(line.AsSpan()[line.LastIndexOf(":")..], out int prevalence))
        {
            prevalence = Random.Shared.Next(100) + 1;
        }

        outputWriter.WriteStartObject();
        outputWriter.WriteString(ntlmName, HashExtensions.CreateNTLMHash(line));
        outputWriter.WriteString(sha1Name, HashExtensions.CreateSHA1Hash(line));
        outputWriter.WriteNumber(numName, prevalence);
        outputWriter.WriteEndObject();
        numPasswords++;
    }
}
outputWriter.WriteEndArray();
await outputWriter.FlushAsync().ConfigureAwait(false);
Console.WriteLine($"Finished preparing {numPasswords} passwords into {args[1]}.");
