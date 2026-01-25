# PE-Sentinel: Binary Forensics and Structural Analysis Platform

PE-Sentinel is a high-fidelity static analysis tool designed for the decomposition and forensic inspection of Windows Portable Executable (PE) files. It extracts structural metadata, calculates entropy distribution, and maps behavioral indicators to provide a comprehensive **Binary DNA** profile.

<img width="1242" height="840" alt="image" src="https://github.com/user-attachments/assets/6cd2ca7e-a6f9-4db2-8fb4-2a76071a8aec" />


## Core Philosophy: Evidence-Based Analysis

In binary forensics, data interpretation is rarely binary. A file may utilize debugger evasion for anti-piracy (benign) or anti-analysis (malicious). PE-Sentinel is built on the principle of **observable forensics**, providing analysts with the data required to form a hypothesis based on empirical evidence rather than opaque black-box verdicts.

* **Observation over Accusation:** The platform visualizes what the file contains and how it is structured without assuming intent.
* **Heuristic Scoring:** A weighted risk model that accounts for the presence or absence of trust signals, such as digital signatures.
* **Contextual Mapping:** Correlation of low-level API calls to the MITRE ATT&CK framework to provide behavioral context.

## Analytical Methodology

### 1. Structural Forensic Engine
The system parses the PE header and section table to identify architectural anomalies. It specifically monitors:
* **Section Alignment:** Identifying non-standard section names or suspicious Virtual-to-Raw size ratios.
* **Entry Point Analysis:** Detecting if the execution starts in an unconventional section, a common trait of manual code injection or packers.
* **Import Address Table (IAT) Profiling:** Deep scanning DLL dependencies to identify capabilities such as network communication, registry manipulation, or process injection.

### 2. Shannon Entropy and Data Density
The platform calculates the entropy of binary data in 4KB chunks to identify regions of high randomness.
* **Packed Code Detection:** Identifying encrypted or compressed stubs that are used to hide malicious payloads.
* **Visual Heatmapping:** A sliding-window analysis provides a visual representation of data density, allowing analysts to pinpoint exactly where hidden resources or encrypted code blocks reside within the binary.



### 3. Threat Pillar Attribution
The analysis engine groups identified traits into four primary pillars to explain the "intent" behind the binary's structure:
* **Capabilities:** Dominant risk factors found in the import table.
* **Stealth:** Indicators of obfuscation, anti-debugging, or anti-VM techniques.
* **Integrity:** Evaluation of trust signals like file signatures and metadata consistency.
* **Intent:** Identifying behavioral contradictions, such as binaries with network capabilities but no user interface.
![Uploading image.png…]()

## Heuristic Weighting Logic

The final observation is generated through a **Calculation Trace** that prioritizes the "worst-case" scenario:
1.  **Structural Discontinuity:** High entropy in a `.text` section triggers an immediate suspicion multiplier.
2.  **Capability Clustering:** Individual API calls (e.g., `VirtualAlloc`) are benign, but when clustered with `WriteProcessMemory` and `CreateRemoteThread`, they are flagged as a **Process Injection** cluster.
3.  **Trust Adjustment:** Digital signatures and valid metadata act as a "score dampener," reducing the final suspicion level of files with legitimate origin.



## Disclaimer

PE-Sentinel is a static analysis tool designed for forensic assistance and educational purposes. Static analysis can be bypassed by advanced runtime obfuscation, and benign files (such as administrative tools or protected software) may trigger suspicious indicators. This tool should be used as one component of a multi-layered investigative process.
