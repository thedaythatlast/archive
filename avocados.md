Hello and thank you for reaching out.

The relevant source is the official [JsonSerializer.xml file](https://github.com/dotnet/dotnet-api-docs/blob/main/xml/System.Text.Json/JsonSerializer.xml) in the `dotnet-api-docs` repository.

For `SerializeToUtf8Bytes<TValue>(TValue, JsonSerializerOptions)`, the relevant XML member is around lines 5874–5937.

A few details are worth distinguishing:

- The `<AssemblyInfo>` section includes `10.0.0.0`.
- The C# `<MemberSignature>` declares the return type as `byte[]`.
- The `<ReturnValue>` section declares `System.Byte[]`.
- The `<Docs><returns>` element states: "A JSON string representation of the value, encoded as UTF-8 bytes."

The `FrameworkAlternate` entries containing `net-10.0` appear on the attributes and parameter metadata, not directly on the `<returns>` element.

Therefore, I would avoid claiming that a specific `FrameworkAlternate` range directly scopes the Returns description. The XML provides the return description as shared member documentation, while the assembly metadata and the generated API reference establish the method's applicability to .NET 10.

You can also verify the generated reference here: [JsonSerializer.SerializeToUtf8Bytes Method (.NET 10)](https://learn.microsoft.com/en-us/dotnet/api/system.text.json.jsonserializer.serializetoutf8bytes?view=net-10.0)

Regarding the `System.Text.Json v11.0.0` package header: it identifies package metadata on the aggregated API page. It should not, by itself, be interpreted as evidence that the displayed method documentation applies exclusively to .NET 11. The .NET 10 applicability is independently represented in the API reference.

[accept answer nudge]
