+++
title = "Silent Bidirectional Audio Interception Across QEMU/KVM Virtualization Boundary"
date = 2017-01-08T00:00:00+00:00

[taxonomies]
tags = ["Features", "Markdown", "Second"]
+++


This research originated from an audio-based post-exploitation project on Linux, which involved building tooling to capture and exfiltrate microphone audio from a compromised host. During simulation of the exploit inside a QEMU/KVM virtual machine, an unexpected observation was made: while music was playing on the host, the VM's audio capture pipeline only recorded the researcher's voice — not the host music.

This triggered a deeper question: how exactly is audio isolated between the host and the VM, and can that isolation boundary be probed or subverted? What followed was a systematic investigation of the audio stack that revealed a significant finding.

<!--more-->

