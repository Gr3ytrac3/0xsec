+++
title = "The Invisible Wire — Covert Channels via File Permission Bits"
date = 2017-01-09T00:00:00+00:00

[taxonomies]
tags = ["Features", "Markdown", "Second"]
+++

<!DOCTYPE html>
</head>
<body>

<!-- HERO -->
<header class="hero">
  <div class="hero-label">Security Research &mdash; Covert Channels</div>
    <p class="subtitle">How two processes can hold a complete conversation without writing a single byte of file content — and why almost nobody would notice.</p>
  </header>

<!-- TOC -->
<div class="toc-wrapper">
  <nav class="toc">
    <div class="toc-title">Table of Contents</div>
    <ol>
      <li><a href="#intro">Introduction</a></li>
      <li><a href="#covert">What Is a Covert Channel?</a></li>
      <li><a href="#permissions">Unix File Permissions as a Data Channel</a></li>
      <li><a href="#protocol">The FPDTP Protocol — A Case Study</a></li>
      <li><a href="#math">The Decoding Math — Step by Step</a></li>
      <li><a href="#interception">Building the Interceptor</a></li>
      <li><a href="#decoder">Writing the Decoder</a></li>
      <li><a href="#realworld">Real-World Threat Scenarios</a></li>
      <li><a href="#detection">Detection and Defense</a></li>
      <li><a href="#conclusion">Conclusion</a></li>
    </ol>
  </nav>
</div>

<main class="article">

<!-- ── 1. INTRODUCTION ── -->
<section id="intro">
  <h2>01. Introduction</h2>
  <p>When most people think about two processes communicating on a Linux system, they think of the obvious channels: TCP sockets, Unix domain sockets, pipes, shared memory, message queues. These are the channels that firewalls watch, that EDR tools monitor, that network analysts capture in pcap files.</p>
  <p>This article is about something else entirely.</p>
  <p>It started with a reverse engineering challenge: two binaries called <strong>alice</strong> and <strong>bob</strong>, a 1.3-second runtime, and the instruction to "intercept the chat messages." No network traffic. No file writes. No pipes. The binaries simply launched, did something invisible, and exited cleanly.</p>
  <p>What they were doing — encoding an entire conversation into Unix file permission metadata — turned out to be a textbook covert channel. And once you understand how it works, you start seeing just how blind most security tooling is to this class of technique.</p>
  <p>This article covers the full picture: the theory behind covert channels, the mechanics of this specific implementation, the decoding math bit by bit, working code to intercept and decode such traffic, and most importantly — what this means for real-world security, both offensive and defensive.</p>

  <div class="callout info">
    <div class="callout-label">Prerequisites</div>
    Basic familiarity with Linux, Python, and binary representations of numbers. Everything else is explained from scratch. If you know what <code>chmod 755</code> means, you have enough background to follow along.
  </div>
</section>

<!-- ── 2. COVERT CHANNELS ── -->
<section id="covert">
  <h2>02. What Is a Covert Channel?</h2>
  <p>A <strong>covert channel</strong> is a communication path that was never intended to be used for communication. Instead of using a legitimate, observable channel, two parties encode information into some aspect of a system that changes state — and that change can be observed by both parties.</p>
  <p>The concept dates back to a 1973 paper by Butler Lampson on the confinement problem. Lampson described a scenario where a malicious process could leak information to an outside observer not by writing files or opening sockets, but by modulating its own CPU usage — which the observer could measure. The observer doesn't read a message; it <em>infers</em> one from a side effect.</p>

  <div class="pullquote">
    <p>"Data can be encoded in anything that changes state — not just file content or network packets."</p>
  </div>

  <h3>Categories of covert channels</h3>
  <p>Covert channels broadly fall into two types:</p>

  <p><strong>Storage channels</strong> encode data by modifying a shared system attribute that another process can read. File permissions, timestamps, process IDs, registry keys, and even the presence or absence of a file are all storage channels. Our case study uses a storage channel.</p>

  <p><strong>Timing channels</strong> encode data by modulating when something happens rather than what it contains. A process sending a "1" bit sleeps for 10ms; sending a "0" bit sleeps for 5ms. The receiver measures the gaps. CPU cache timing attacks like Spectre and Meltdown are timing channels operating at the nanosecond level.</p>

  <div class="callout">
    <div class="callout-label">Real-World Examples</div>
    <strong>CVE-2022-0185</strong> — Linux kernel heap overflow exploited via inotify covert signaling between processes. <strong>DNS tunneling</strong> — encoding data in DNS query hostnames to exfiltrate across firewalls that allow DNS. <strong>ICMP tunneling</strong> — embedding payloads in ping packet data fields. All covert channels. All have been used in production malware.
  </div>
</section>

<!-- ── 3. FILE PERMISSIONS ── -->
<section id="permissions">
  <h2>03. Unix File Permissions as a Data Channel</h2>
  <p>Every file and directory on a Linux system carries a 12-bit permission field. The lower 9 bits are the familiar <code>rwxrwxrwx</code> — three groups of three bits controlling read, write, and execute access for the owner, group, and others.</p>

  <div class="bitdiagram">
    <span class="label">Permission string:  </span><span class="val">r w x r - x r - -</span><br>
    <span class="label">Bit representation: </span><span class="hi">1 1 1</span> <span class="lo">1 0 1</span> <span class="val">1 0 0</span><br>
    <span class="label">Octal:              </span><span class="hi">7</span><span class="lo">5</span><span class="val">4</span>  <span class="comment">→  0o754  →  decimal 492</span>
  </div>

  <p>This field is <strong>metadata</strong> — it lives in the inode, not in the file's data blocks. You set it with <code>chmod()</code> and read it with <code>stat()</code>. Crucially, modifying file permissions leaves no trace in the file's content. It doesn't show up in a hexdump. It doesn't change the file's hash. Network monitoring tools ignore it entirely.</p>

  <h3>Why permissions make an effective covert channel</h3>

  <p>Three properties make file permissions unusually good for covert communication:</p>

  <p><strong>1. Volatile.</strong> Permissions can be changed thousands of times per second. The inode update is an in-memory operation on most filesystems. There is no rate limiting.</p>

  <p><strong>2. Readable without ownership.</strong> Any process that can <code>stat()</code> a file can read its permissions — regardless of whether it has read access to the file's content. A file with mode <code>0o000</code> (no permissions for anyone) can still have its permission bits read and changed by its owner.</p>

  <p><strong>3. Off the radar.</strong> Standard security monitoring focuses on file reads and writes, network connections, and process execution. The <code>chmod</code> syscall is rarely logged, rarely alerted on, and almost never inspected for encoded content.</p>

  <div class="callout danger">
    <div class="callout-label">Attacker Perspective</div>
    A malware implant communicating via file permission bits generates no network traffic, writes no data to disk, and produces no anomalous file reads or writes. On a system without <code>auditd</code> configured to watch <code>chmod</code> syscalls specifically, this communication is effectively invisible.
  </div>
</section>

<!-- ── 4. THE PROTOCOL ── -->
<section id="protocol">
  <h2>04. The FPDTP Protocol — A Case Study</h2>
  <p>The challenge binary implements what it calls the <strong>File Permission Data Transfer Protocol</strong> (FPDTP). Two binaries — alice and bob — communicate entirely through the permission bits of a single shared file: <code>/tmp/fpdtp_pipe</code>.</p>

  <p>The file is created by bob on launch. Its content stays empty throughout the session. Alice and bob coordinate entirely through the file's mode field, which they update via <code>chmod()</code> and read via <code>stat()</code>.</p>

  <h3>Discovering the shared file</h3>
  <p>Static analysis with <code>strings</code> and <code>objdump</code> reveals the channel:</p>

  <div class="codeblock">
    <div class="codeblock-header"><span class="codeblock-lang">bash</span></div>
    <pre>strings bob | grep -E '(/tmp|chmod|stat)'
<span class="c"># Output: /tmp/fpdH  (mangled artifact — not the real path)</span>

objdump -d alice | grep -E 'chmod|stat|notify'
<span class="c"># Output: stat calls throughout — no sockets, no pipes</span>

<span class="c"># Runtime observation:</span>
ls /tmp/ | grep fpdtp   <span class="c"># before launching: nothing</span>
<span class="c"># launch bob, then alice...</span>
ls /tmp/ | grep fpdtp   <span class="c"># during execution: fpdtp_pipe appears</span></pre>
  </div>

  <p>The actual path <code>/tmp/fpdtp_pipe</code> was discovered by watching <code>/tmp/</code> live during execution — the <code>strings</code> output was misleading due to how the string was stored in the binary. This is a common RE gotcha: always verify static findings against runtime behavior.</p>

  <h3>The handshake</h3>
  <p>Bob launches first and prints <strong>needs sync</strong>. Alice launches and both print <strong>sync acknowledge</strong>. The handshake establishes that both parties are ready, then the conversation begins immediately. Total runtime: approximately 1.3 seconds.</p>

  <h3>Protocol structure</h3>
  <p>After capturing permission changes with a Python interceptor (built in section 6), the raw values reveal a clear structure:</p>

  <div class="bitdiagram">
    <span class="comment">── Session framing ──────────────────────────────────────</span><br>
    <span class="label">0o0   </span><span class="comment">←  idle / separator between bytes</span><br>
    <span class="label">0o4   </span><span class="comment">←  session start marker (header)</span><br>
    <span class="label">0o10  </span><span class="comment">←  session end marker (trailer)</span><br>
    <br>
    <span class="comment">── One character exchange ────────────────────────────────</span><br>
    <span class="label">0o0   </span><span class="comment">←  separator</span><br>
    <span class="hi"><span class="label">0o142 </span><span class="comment">←  Alice sets data value (even)</span></span><br>
    <span class="hi"><span class="label">0o143 </span><span class="comment">←  Alice signals "written" (+1, execute bit)</span></span><br>
    <span class="lo"><span class="label">0o202 </span><span class="comment">←  Bob sets data value (even)</span></span><br>
    <span class="lo"><span class="label">0o203 </span><span class="comment">←  Bob signals "written" (+1, execute bit)</span></span><br>
    <span class="label">0o0   </span><span class="comment">←  separator</span><br>
    <br>
    <span class="comment">── Message boundaries ────────────────────────────────────</span><br>
    <span class="label">0x00  </span><span class="comment">←  end of one speaker's message</span><br>
    <span class="label">0x0a  </span><span class="comment">←  newline between turns</span>
  </div>

  <p>The key insight: values always appear in <strong>even/odd pairs</strong> differing by exactly 1. The even value carries the data. The odd value (even | 1) is a signal — toggling the execute bit to say "I have written my contribution, your turn." This is a minimal handshake protocol using a single bit as a semaphore.</p>
</section>

<!-- ── 5. THE MATH ── -->
<section id="math">
  <h2>05. The Decoding Math — Step by Step</h2>
  <p>This is the core of the article. Let's walk through exactly how a raw octal permission value becomes a letter of the alphabet. No shortcuts.</p>

  <h3>Step 1 — What is an octal number?</h3>
  <p>Octal is base 8. Where decimal (base 10) uses digits 0–9, octal uses only 0–7. The prefix <code>0o</code> in Python denotes an octal literal. The reason Unix permissions use octal is elegant: each octal digit represents exactly 3 binary bits, and permissions are divided into three groups of 3 bits (owner, group, other) — so one octal digit maps perfectly to one permission group.</p>

  <div class="bitdiagram">
    <span class="comment">Each octal digit = 3 binary bits:</span><br>
    <span class="label">0  </span><span class="val">=  000</span><br>
    <span class="label">1  </span><span class="val">=  001</span><br>
    <span class="label">2  </span><span class="val">=  010</span><br>
    <span class="label">4  </span><span class="val">=  100</span><br>
    <span class="label">7  </span><span class="val">=  111  (rwx)</span><br>
    <br>
    <span class="comment">0o754 → owner=7(rwx), group=5(r-x), other=4(r--)</span>
  </div>

  <h3>Step 2 — The 16-value constraint</h3>
  <p>Examining all captured permission values reveals only 16 unique even values:</p>

  <table class="datatable">
    <thead>
      <tr><th>Octal</th><th>Decimal</th><th>Binary (9-bit)</th><th>Nibble (>> 4)</th></tr>
    </thead>
    <tbody>
      <tr><td class="accent">0o002</td><td>2</td><td>000 000 010</td><td class="green">0</td></tr>
      <tr><td class="accent">0o022</td><td>18</td><td>000 010 010</td><td class="green">1</td></tr>
      <tr><td class="accent">0o042</td><td>34</td><td>000 100 010</td><td class="green">2</td></tr>
      <tr><td class="accent">0o062</td><td>50</td><td>000 110 010</td><td class="green">3</td></tr>
      <tr><td class="accent">0o102</td><td>66</td><td>001 000 010</td><td class="green">4</td></tr>
      <tr><td class="accent">0o122</td><td>82</td><td>001 010 010</td><td class="green">5</td></tr>
      <tr><td class="accent">0o142</td><td>98</td><td>001 100 010</td><td class="green">6</td></tr>
      <tr><td class="accent">0o162</td><td>114</td><td>001 110 010</td><td class="green">7</td></tr>
      <tr><td class="accent">0o202</td><td>130</td><td>010 000 010</td><td class="green">8</td></tr>
      <tr><td class="accent">0o222</td><td>146</td><td>010 010 010</td><td class="green">9</td></tr>
      <tr><td class="accent">0o242</td><td>162</td><td>010 100 010</td><td class="green">10 (A)</td></tr>
      <tr><td class="accent">0o262</td><td>178</td><td>010 110 010</td><td class="green">11 (B)</td></tr>
      <tr><td class="accent">0o302</td><td>194</td><td>011 000 010</td><td class="green">12 (C)</td></tr>
      <tr><td class="accent">0o322</td><td>210</td><td>011 010 010</td><td class="green">13 (D)</td></tr>
      <tr><td class="accent">0o342</td><td>226</td><td>011 100 010</td><td class="green">14 (E)</td></tr>
      <tr><td class="accent">0o362</td><td>242</td><td>011 110 010</td><td class="green">15 (F)</td></tr>
    </tbody>
  </table>

  <p>Exactly 16 values. 16 = 2⁴ = the number of possible values for a <strong>nibble</strong> (4 bits, half a byte). This is not a coincidence — each permission value encodes exactly one nibble of the message.</p>

  <p>The pattern: every value is <code>n × 16 + 2</code>, where <code>n</code> is the nibble (0–15). The constant <code>+2</code> means the <em>other-write</em> bit (<code>-w-</code> for others) is always set. This is just the encoding baseline — meaningless from a permissions standpoint, but consistent.</p>

  <h3>Step 3 — Extracting the nibble</h3>
  <p>Given a permission value, extracting the nibble is a single operation: shift right by 4 bits.</p>

  <div class="bitdiagram">
    <span class="comment">Extract nibble from 0o142 (decimal 98):</span><br>
    <br>
    <span class="label">0o142 in binary:  </span><span class="hi">0 0 1 1</span> <span class="lo">0 0 0</span> <span class="val">1 0</span><br>
    <span class="label">                  </span><span class="hi">^^^^^^^^</span><span class="comment"> ← nibble lives here (upper bits)</span><br>
    <span class="label">                  </span><span class="comment">         </span><span class="lo">^^^^^^^</span><span class="comment"> ← encoding baseline + signal bit</span><br>
    <br>
    <span class="label">Strip signal bit: </span><span class="val">98 &amp; ~1  =  98 &amp; 0b11111110  =  98</span><br>
    <span class="label">Shift right 4:    </span><span class="val">98 &gt;&gt; 4  =  6</span><br>
    <br>
    <span class="result">Nibble = 6  →  hex digit 0x6</span>
  </div>

  <h3>Step 4 — Combining two nibbles into a byte</h3>
  <p>Alice contributes the <strong>high nibble</strong> (upper 4 bits of the byte). Bob contributes the <strong>low nibble</strong> (lower 4 bits). Together they form one complete ASCII byte.</p>

  <div class="bitdiagram">
    <span class="comment">Decoding the letter 'h':</span><br>
    <br>
    <span class="hi"><span class="label">Alice sets 0o142: </span><span class="val">nibble = 0o142 &gt;&gt; 4 = 6  →  0110 in binary</span></span><br>
    <span class="lo"><span class="label">Bob sets   0o202: </span><span class="val">nibble = 0o202 &gt;&gt; 4 = 8  →  1000 in binary</span></span><br>
    <br>
    <hr>
    <span class="label">Combine:          </span><span class="hi">0110</span><span class="lo">1000</span>  <span class="comment">← (6 &lt;&lt; 4) | 8</span><br>
    <span class="label">In hex:           </span><span class="result">0x68</span><br>
    <span class="label">ASCII table:      </span><span class="result">0x68 = 104 = 'h'  ✓</span>
  </div>

  <div class="bitdiagram">
    <span class="comment">Decoding the letter 'i':</span><br>
    <br>
    <span class="hi"><span class="label">Alice sets 0o142: </span><span class="val">nibble = 6</span></span><br>
    <span class="lo"><span class="label">Bob sets   0o222: </span><span class="val">nibble = 0o222 &gt;&gt; 4 = 9</span></span><br>
    <br>
    <hr>
    <span class="label">Combine:          </span><span class="hi">0110</span><span class="lo">1001</span>  <span class="comment">← (6 &lt;&lt; 4) | 9</span><br>
    <span class="label">In hex:           </span><span class="result">0x69</span><br>
    <span class="label">ASCII table:      </span><span class="result">0x69 = 105 = 'i'  ✓</span>
  </div>

  <p>Repeat for every group of four values (separated by <code>0o0</code>) and you decode the entire message, character by character.</p>

  <h3>Step 5 — The full decoded conversation</h3>

  <div class="conversation">
    <div><span class="msg-label">[Bob]</span>   <span class="msg-bob">hi alice!</span></div>
    <div><span class="msg-label">[Alice]</span> <span class="msg-alice">what's up bob??</span></div>
    <div><span class="msg-label">[Bob]</span>   <span class="msg-bob">the sky of course o.O</span></div>
    <div><span class="msg-label">[Alice]</span> <span class="msg-alice">you should update your sense of humor</span></div>
    <div><span class="msg-label">[Bob]</span>   <span class="msg-bob">can't... I'm using debian</span></div>
  </div>

  <p>119 bytes. 5 messages. Transmitted entirely through file permission metadata. Zero bytes of file content written.</p>
</section>

<!-- ── 6. INTERCEPTOR ── -->
<section id="interception">
  <h2>06. Building the Interceptor</h2>
  <p>The interceptor needs to capture every permission change on <code>/tmp/fpdtp_pipe</code> in real time. The challenge: the entire conversation happens in ~1.3 seconds, meaning some permission changes occur within microseconds of each other.</p>

  <h3>Why strace failed</h3>
  <p>The natural first instinct is <code>strace -e trace=chmod</code>. This fails for a timing reason: strace attaches to a running process. By the time you attach, the conversation may be halfway done. You need to be watching <em>before</em> the first chmod call. The solution is to not attach to the process at all — instead, watch the shared file from the outside.</p>

  <h3>The polling interceptor</h3>
  <p>The working approach: a tight polling loop that <code>stat()</code>s the file as fast as Python can and logs every permission change. The critical parameters are: start the interceptor <em>before</em> launching either binary, and keep the sleep interval as small as possible.</p>

  <div class="codeblock">
    <div class="codeblock-header"><span class="codeblock-lang">python</span></div>
    <pre><span class="k">import</span> os
<span class="k">import</span> time

path = <span class="s">"/tmp/fpdtp_pipe"</span>
last = <span class="k">None</span>

<span class="c"># Wait for file to appear — no sleep, spin hard</span>
<span class="n">print</span>(<span class="s">"[*] Waiting for fpdtp_pipe..."</span>)
<span class="k">while not</span> os.path.exists(path):
    <span class="k">pass</span>

<span class="n">print</span>(<span class="s">"[*] File detected! Intercepting...\n"</span>)

<span class="k">while True</span>:
    <span class="k">try</span>:
        mode = os.stat(path).st_mode & <span class="m">0o777</span>
        <span class="k">if</span> mode != last <span class="k">and</span> mode != <span class="m">0</span>:
            <span class="n">print</span>(oct(mode))
            last = mode
    <span class="k">except</span> FileNotFoundError:
        <span class="n">print</span>(<span class="s">"\n[*] File removed — session ended."</span>)
        <span class="k">break</span>
    <span class="k">except</span>:
        <span class="k">pass</span>

    time.sleep(<span class="m">0.000001</span>)  <span class="c"># 1 microsecond — 100x tighter than default</span></pre>
  </div>

  <div class="callout">
    <div class="callout-label">Practical Note</div>
    Polling reliability is sensitive to system load. Running background applications (browser, IDE, terminals) introduces OS scheduling interference that causes missed values. For a clean capture, close unnecessary processes before running the interceptor. On a busy system, the event-driven alternative using <code>inotify IN_ATTRIB</code> via <code>ctypes</code> is more reliable — it fires the instant the kernel processes the chmod call, with no polling gap.
  </div>
</section>

<!-- ── 7. DECODER ── -->
<section id="decoder">
  <h2>07. Writing the Decoder</h2>
  <p>With a clean capture in hand, the decoder implements the math from section 5 in five clean steps.</p>

  <div class="codeblock">
    <div class="codeblock-header"><span class="codeblock-lang">python — fpdtp_decoder.py</span></div>
    <pre><span class="k">def</span> <span class="n">decode_fpdtp</span>(raw_values):
    <span class="s">"""
    Decode FPDTP permission-encoded chat traffic.
    Input:  list of octal permission values from interceptor
    Output: decoded conversation printed to stdout
    """</span>

    <span class="c"># ── Step 1: split on 0o0 separators into groups ──────────</span>
    groups = []
    current = []
    <span class="k">for</span> v <span class="k">in</span> raw_values:
        <span class="k">if</span> v == <span class="m">0</span>:
            <span class="k">if</span> current:
                groups.append(current)
            current = []
        <span class="k">else</span>:
            current.append(v)
    <span class="k">if</span> current:
        groups.append(current)

    <span class="c"># ── Step 2: skip header (groups[0]) and trailer (groups[-1])</span>
    data_groups = groups[<span class="m">1</span>:<span class="m">-1</span>]

    <span class="c"># ── Step 3: decode each group into one byte ───────────────</span>
    message_bytes = []
    <span class="k">for</span> group <span class="k">in</span> data_groups:

        <span class="c"># Extract pairs: v and v+1 = one nibble contribution</span>
        <span class="c"># Strip the +1 signal bit; keep only the data value</span>
        pairs = []
        j = <span class="m">0</span>
        <span class="k">while</span> j < len(group):
            <span class="k">if</span> j+<span class="m">1</span> < len(group) <span class="k">and</span> group[j+<span class="m">1</span>] == (group[j] | <span class="m">1</span>):
                pairs.append(group[j] & ~<span class="m">1</span>)  <span class="c"># clear signal bit</span>
                j += <span class="m">2</span>
            <span class="k">else</span>:
                pairs.append(group[j] & ~<span class="m">1</span>)
                j += <span class="m">1</span>

        <span class="c"># Need at least two nibbles to form one byte</span>
        <span class="k">if</span> len(pairs) >= <span class="m">2</span>:
            high_nibble = pairs[<span class="m">0</span>] >> <span class="m">4</span>   <span class="c"># Alice's contribution</span>
            low_nibble  = pairs[<span class="m">1</span>] >> <span class="m">4</span>   <span class="c"># Bob's contribution</span>
            byte = (high_nibble << <span class="m">4</span>) | low_nibble
            message_bytes.append(byte)

    <span class="c"># ── Step 4: split into messages on 0x00 boundary ─────────</span>
    <span class="c"># Skip first 2 bytes (protocol header: 0x42, 0xF1)</span>
    messages = []
    current_msg = []
    <span class="k">for</span> b <span class="k">in</span> message_bytes[<span class="m">2</span>:]:
        <span class="k">if</span> b == <span class="m">0x00</span>:
            <span class="k">if</span> current_msg:
                messages.append(bytes(current_msg))
                current_msg = []
        <span class="k">elif</span> b != <span class="m">0x0a</span>:    <span class="c"># skip newline separators</span>
            current_msg.append(b)

    <span class="c"># ── Step 5: print the conversation ───────────────────────</span>
    speakers = [<span class="s">'Bob'</span>, <span class="s">'Alice'</span>, <span class="s">'Bob'</span>, <span class="s">'Alice'</span>, <span class="s">'Bob'</span>]
    <span class="n">print</span>(<span class="s">"=" * 42</span>)
    <span class="k">for</span> i, msg <span class="k">in</span> enumerate(messages):
        speaker = speakers[i] <span class="k">if</span> i < len(speakers) <span class="k">else</span> <span class="s">'?'</span>
        <span class="n">print</span>(<span class="s">f"  [{speaker}]: {msg.decode('ascii')}"</span>)
    <span class="n">print</span>(<span class="s">"=" * 42</span>)</pre>
  </div>

  <p>Running the decoder against a clean capture produces zero incomplete groups and the full conversation decoded correctly. The entire pipeline — from raw permission values to readable text — is fewer than 50 lines of Python.</p>
</section>

<!-- ── 8. REAL WORLD ── -->
<section id="realworld">
  <h2>08. Real-World Threat Scenarios</h2>
  <p>What makes this technique genuinely dangerous in a real-world context isn't the CTF implementation — it's that the underlying primitive is completely general. Any two processes that share a filesystem can use this channel. Let's examine concrete threat scenarios.</p>

  <h3>Scenario 1 — C2 communication on an air-gapped host</h3>
  <p>An implant is deployed on a system with no outbound network access. A second stage payload is dropped separately (via USB, supply chain, or a previously compromised process). The two components need to coordinate without generating network traffic.</p>
  <p>Using file permission bits, the first stage can receive commands encoded in permission changes on a file in <code>/tmp</code>. The second stage sets permissions to encode each byte of the command. No socket. No pipe. No network connection. The communication is invisible to any network-based monitoring.</p>

  <h3>Scenario 2 — Container escape coordination</h3>
  <p>A compromised containerized process wants to signal a host-level process without breaking out of its namespace directly. If a host-mounted volume is accessible from within the container, permission changes on that shared filesystem are visible to both sides. The channel crosses the container boundary without any direct process communication.</p>

  <h3>Scenario 3 — Privilege escalation signaling</h3>
  <p>A low-privilege process needs to signal a high-privilege process to take a specific action — write a file, execute a command, modify a configuration. Direct IPC between different privilege levels is restricted. But both can read and write permission bits on a world-accessible file in <code>/tmp</code>. The low-privilege process encodes a command in permission changes. The high-privilege process polls for the signal.</p>

  <h3>Scenario 4 — Slow exfiltration with minimal footprint</h3>
  <p>An attacker has persistent access to a system and wants to exfiltrate data gradually without triggering anomaly detection on file sizes or network volume. Using permission bits, data is exfiltrated at ~9 bits per chmod call. At 1000 chmod calls per second, that's ~112 bytes per second — slow but steady, and completely off the radar of tools that watch data volume.</p>

  <div class="callout danger">
    <div class="callout-label">Key Insight</div>
    The bandwidth of a file-permission covert channel is inherently limited — roughly 4 bits per chmod call, constrained by the speed of the <code>stat()</code>/<code>chmod()</code> syscall pair. But for command-and-control traffic, which is often just short commands and acknowledgements, this bandwidth is more than sufficient.
  </div>
</section>

<!-- ── 9. DETECTION ── -->
<section id="detection">
  <h2>09. Detection and Defense</h2>
  <p>Detecting covert channel abuse is fundamentally harder than detecting direct exfiltration, because the data never appears in any standard monitoring surface. However, the technique does leave detectable footprints if you know where to look.</p>

  <h3>Detection method 1 — auditd chmod monitoring</h3>
  <p>The Linux Audit subsystem can log every <code>chmod</code> syscall system-wide. Adding a rule to watch for unusually frequent permission changes on <code>/tmp</code> files will catch this pattern:</p>

  <div class="codeblock">
    <div class="codeblock-header"><span class="codeblock-lang">bash — auditd rule</span></div>
    <pre><span class="c"># Log all chmod calls on /tmp/</span>
auditctl -w /tmp/ -p a -k tmp_chmod_watch

<span class="c"># Then watch for bursts: 100+ chmod calls in 2 seconds</span>
<span class="c"># on the same file is highly anomalous normal behavior</span>
ausearch -k tmp_chmod_watch | grep chmod | \
  awk '{print $NF}' | sort | uniq -c | sort -rn</pre>
  </div>

  <h3>Detection method 2 — inotify-based watchdog</h3>
  <p>A lightweight daemon watching <code>/tmp</code> for <code>IN_ATTRIB</code> events (attribute changes, which includes permission changes) can alert when a file's permissions change more than a threshold number of times per second:</p>

  <div class="codeblock">
    <div class="codeblock-header"><span class="codeblock-lang">python — permission change monitor</span></div>
    <pre><span class="k">import</span> ctypes, os, time
<span class="k">from</span> collections <span class="k">import</span> defaultdict

libc = ctypes.CDLL(<span class="s">"libc.so.6"</span>)
THRESHOLD = <span class="m">20</span>   <span class="c"># alerts if file changes > 20 times/second</span>
IN_ATTRIB = <span class="m">0x00000004</span>
IN_CREATE = <span class="m">0x00000100</span>

fd = libc.inotify_init()
libc.inotify_add_watch(fd, <span class="s">b"/tmp"</span>, IN_ATTRIB | IN_CREATE)
buf = ctypes.create_string_buffer(<span class="m">4096</span>)
change_counts = defaultdict(list)

<span class="k">while True</span>:
    libc.read(fd, buf, <span class="m">4096</span>)
    now = time.time()
    <span class="c"># parse inotify event to get filename (simplified)</span>
    <span class="c"># track changes per file per second</span>
    <span class="c"># alert if rate exceeds threshold</span></pre>
  </div>

  <h3>Detection method 3 — behavioral anomaly</h3>
  <p>Even without specific tooling, the behavioral signature is distinctive. A file in <code>/tmp</code> that has its permissions changed hundreds of times in under two seconds, with content that remains empty throughout, has no legitimate explanation. SIEM rules or EDR behavioral policies can encode this heuristic.</p>

  <h3>Mitigation strategies</h3>
  <ul>
    <li><strong>Mount /tmp with noexec and restricted permissions</strong> — limits what processes can be created there but does not prevent permission metadata abuse</li>
    <li><strong>Deploy auditd with chmod rules</strong> — the most direct detection path; log and alert on anomalous chmod frequency</li>
    <li><strong>Containerization with read-only /tmp mounts</strong> — removes the shared filesystem needed for cross-process covert channels</li>
    <li><strong>Process isolation</strong> — if two processes don't need to share a filesystem, don't give them one; namespaced /tmp per process group eliminates the shared channel</li>
    <li><strong>Baseline chmod frequency</strong> — establish what normal looks like on your systems; covert channel traffic stands out against a clean baseline</li>
  </ul>

  <div class="callout success">
    <div class="callout-label">Defender's Summary</div>
    The single most effective control is <strong>auditd with chmod syscall logging on /tmp</strong>. A legitimate process rarely changes file permissions more than a handful of times per session. A covert channel generating 100+ chmod calls per second is a strong anomaly signal that existing tools will catch if you configure them to look.
  </div>
</section>

<!-- ── 10. CONCLUSION ── -->
<section id="conclusion">
  <h2>10. Conclusion</h2>
  <p>The FPDTP challenge is, on the surface, a clever CTF puzzle. Underneath, it demonstrates a communication primitive that is genuinely underappreciated from a security standpoint.</p>
  <p>File permissions are ubiquitous, fast to modify, and almost universally ignored by security tooling. The encoding technique — splitting bytes into nibbles across two cooperating processes — is simple enough to implement in under 100 lines of C, yet sophisticated enough to evade network-based monitoring entirely.</p>
  <p>The lessons here operate at multiple levels. For defenders: your monitoring stack needs to include metadata-level visibility, not just content and network visibility. For researchers: covert channels are not just academic curiosities — they are practical techniques with real attacker utility, especially in constrained environments. For anyone learning security through CTF: the gap between "this is a puzzle" and "this is a real attack primitive" is often smaller than it looks.</p>

  <div class="pullquote">
    <p>"The most dangerous channel is the one nobody thought to monitor."</p>
  </div>

  <p>If you want to explore further, the natural extensions of this research are: timing-based variants (encoding data in the delay between chmod calls rather than their values), multi-file channels (using a directory of files where the presence/absence encodes bits), and filesystem-agnostic implementations using inode change timestamps instead of permission bits.</p>
  <p>The invisible wire is everywhere. Start looking for it.</p>
</section>

</main>

<footer>
  <div>The Invisible Wire — Covert Channels via File Permission Bits</div>
  <div>March 2026 &mdash; Security Research</div>
</footer>

</body>
</html>
