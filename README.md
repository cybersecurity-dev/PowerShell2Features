<div align="center">

```mermaid
flowchart LR
    PS["PowerShell Script"]

    subgraph G1["Group 1: Text and Lexical Structure"]
        T1["Taxonomy: Lexical Features"]
        T2["Taxonomy: Tokens and Vocabulary"]
        C1["Characters, quoting, escaping, whitespace, lines"]
        C2["Tokens, keywords, operators, n-grams, TF-IDF"]
    end

    subgraph G2["Group 2: Commands and Data Elements"]
        T3["Taxonomy: Cmdlets, Commands, and Aliases"]
        T4["Taxonomy: Variables and Parameters"]
        C3["Command identity, frequency, aliases, pipelines"]
        C4["Variables, parameters, scopes, identifiers"]
    end

    subgraph G3["Group 3: Content and Indicators"]
        T5["Taxonomy: Strings and Indicators"]
        T6["Taxonomy: .NET and Platform References"]
        C5["URLs, domains, IPs, paths, registry, commands"]
        C6["Types, members, assemblies, WMI, COM, native APIs"]
    end

    subgraph G4["Group 4: Structure and Behavioral Indicators"]
        T7["Taxonomy: Control and Script Structure"]
        T8["Taxonomy: Behavioral Command Categories"]
        C7["Functions, conditions, loops, exceptions, pipelines"]
        C8["Download, execution, persistence, discovery, security"]
    end

    subgraph G5["Group 5: Obfuscation and Embedded Content"]
        T9["Taxonomy: Obfuscation Indicators"]
        T10["Taxonomy: Encoding and Embedded Content"]
        C9["Concatenation, escaping, format, replacement, invocation"]
        C10["Base64, hex, byte arrays, compression, embedded payloads"]
    end

    subgraph G6["Group 6: Statistics and Metadata"]
        T11["Taxonomy: Entropy and Aggregate Statistics"]
        T12["Taxonomy: Comments and Script Metadata"]
        C11["Entropy, counts, ratios, density, complexity"]
        C12["Comments, help, signatures, modules, requirements"]
    end

    subgraph FEATURES["Features Grouped by Taxonomy"]
        F1["Lexical: character classes, quotes, escapes, line statistics"]
        F2["Tokens: counts, types, vocabulary, n-grams, TF-IDF"]
        F3["Commands: cmdlets, aliases, frequency, pipeline statistics"]
        F4["Variables: names, scopes, parameters, environment variables"]
        F5["Strings: lengths, entropy, URLs, IPs, paths, registry keys"]
        F6["Platform: .NET types, reflection, assemblies, WMI, COM"]
        F7["Structure: functions, branches, loops, try-catch, nesting"]
        F8["Behavior: network, process, persistence, discovery, defense"]
        F9["Obfuscation: escaping, concatenation, format, dynamic invoke"]
        F10["Embedded: encoded commands, Base64, bytes, compressed data"]
        F11["Statistics: entropy, histograms, counts, ratios, complexity"]
        F12["Metadata: comments, help, signature, modules, script encoding"]
    end

    subgraph ML["ML-Ready Representation"]
        NUM["Numeric"]
        CAT["Categorical"]
        BIN["Binary"]
        SP["Sparse Vocabulary"]

        FV["PowerShell Static Feature Vector"]
        PREP["Imputation, Encoding, Scaling, Selection"]
        MODEL["Malicious-Script Detection or Family Model"]
    end

    PS --> T1 & T2 & T3 & T4 & T5 & T6
    PS --> T7 & T8 & T9 & T10 & T11 & T12

    T1 --> C1 --> F1
    T2 --> C2 --> F2
    T3 --> C3 --> F3
    T4 --> C4 --> F4
    T5 --> C5 --> F5
    T6 --> C6 --> F6
    T7 --> C7 --> F7
    T8 --> C8 --> F8
    T9 --> C9 --> F9
    T10 --> C10 --> F10
    T11 --> C11 --> F11
    T12 --> C12 --> F12

    F1 --> NUM
    F2 --> SP
    F3 --> SP
    F4 --> NUM
    F5 --> SP
    F6 --> SP
    F7 --> NUM
    F8 --> NUM
    F9 --> NUM
    F10 --> BIN
    F11 --> NUM
    F12 --> BIN

    NUM --> FV
    CAT --> FV
    BIN --> FV
    SP --> FV

    FV --> PREP --> MODEL

    classDef input fill:#263238,color:#ffffff,stroke:#000000,stroke-width:2px;
    classDef taxonomy fill:#e3f2fd,color:#0d47a1,stroke:#1976d2,stroke-width:2px;
    classDef category fill:#fff3e0,color:#e65100,stroke:#fb8c00;
    classDef feature fill:#e8f5e9,color:#1b5e20,stroke:#43a047;
    classDef output fill:#00695c,color:#ffffff,stroke:#004d40,stroke-width:2px;

    class PS input;
    class T1,T2,T3,T4,T5,T6,T7,T8,T9,T10,T11,T12 taxonomy;
    class C1,C2,C3,C4,C5,C6,C7,C8,C9,C10,C11,C12 category;
    class F1,F2,F3,F4,F5,F6,F7,F8,F9,F10,F11,F12 feature;
    class NUM,CAT,BIN,SP,FV,PREP,MODEL output;
```

# **`PS2Features`** | PowerShell Feature Extraction Framework for Malware Detection
</div>

[![YouTube](https://img.shields.io/badge/YouTube-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)]()
[![Reddit](https://img.shields.io/badge/Reddit-FF4500?style=for-the-badge&logo=reddit&logoColor=white)]()

<p align="center">
    <a href="https://github.com/cybersecurity-dev/"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/github.svg" alt="GitHub"></a>
    &nbsp;
    <a href="https://www.youtube.com/@CyberThreatDefense"><img height="25" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/youtube.svg" alt="YouTube"></a>
    &nbsp;
    <a href="https://cyberthreatdefence.com/my_awesome_lists"><img height="20" src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/blog.svg" alt="My Awesome Lists"></a>
    <img src="https://github.com/cybersecurity-dev/cybersecurity-dev/blob/main/assets/bar.gif">
</p>


## Extraction Framework

| Extracted Feature | [Parser Class](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.language.parser) | [PSScriptAnalyzer](https://learn.microsoft.com/en-us/powershell/utility-modules/psscriptanalyzer/overview?view=ps-modules) | [PSParser Class](https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.psparser) | [tree-sitter-powershell](https://github.com/airbus-cert/tree-sitter-powershell) | [Semgrep](https://semgrep.dev/) | [Joern](https://joern.io/) | [Regex](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Regular_expressions) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| String and Literal Extraction | ✅ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| Comment Extraction | ✅ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ✅ |
| Token Extraction | ✅ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ | ⚠️ |
| Variable Extraction | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ⚠️ |
| Function Extraction | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ⚠️ |
| Parameter Extraction | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ⚠️ |
| Cmdlet and Command Extraction | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ |
| Alias Extraction and Resolution | ⚠️ | ✅ | ⚠️ | ⚠️ | ⚠️ | ❌ | ⚠️ |
| Module and Dependency Extraction | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ⚠️ |
| .NET API Call Extraction | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ⚠️ |
| Native Executable Call Extraction | ✅ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ |
| WMI and CIM Call Extraction | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Registry Operation Extraction | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| File-System Operation Extraction | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Network Operation Extraction | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Process-Creation Extraction | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Scheduled-Task and Service Extraction | ✅ | ⚠️ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Encoded Command Detection | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ | ✅ |
| Obfuscation Indicator Extraction | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ | ✅ |
| Dynamic Execution Detection | ✅ | ✅ | ⚠️ | ✅ | ✅ | ⚠️ | ✅ |
| Download-and-Execute Pattern Detection | ⚠️ | ⚠️ | ⚠️ | ⚠️ | ✅ | ⚠️ | ✅ |
