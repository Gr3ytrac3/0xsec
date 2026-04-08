+++
title = "Building my QEMU/KVM Lab on Fedora 42 (External SSD Storage)"
date = 2025-08-21T00:00:00+00:00
[taxonomies]
tags = ["Virtualization", "QEMU", "KVM", "Fedora", "Homelab", "Security Lab", "libvirt"]
+++

My CPU could handle VMs, but internal storage couldn't. I split my external drive into a dedicated `vm_storage` partition for ISOs and qcow2 disks.

![QEMU/KVM Lab on Fedora 42](https://raw.githubusercontent.com/Gr3ytrac3/KVM/8c05cf5fe85e32ac140fcf03d6fc4090e5f14166/Screenshot%20From%202025-08-21%2020-18-05.png)

<!--more-->

### What's inside

- KVM/libvirt install & enable
- Permanent mount via `/etc/fstab`
- SELinux labels that actually work
- Libvirt storage pools (`vm_storage`, `VMs_iso`)
- VM creation flow + GRUB on the *virtual* disk
- Screenshot-backed steps for each stage

> **Bonus:** safely attach another partition read-only or use virtiofs to copy files into VMs — no corruption, no drama.

If you're into virtualization, homelab, or security labs, this will save you time.

![Lab setup screenshot](https://substackcdn.com/image/fetch/$s_!8emd!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2Fc0fca96f-8278-44da-8b28-886e77b6c3f3_1920x1080.jpeg)

![Lab setup screenshot 2](https://substackcdn.com/image/fetch/$s_!Bsqt!,f_auto,q_auto:good,fl_progressive:steep/https%3A%2F%2Fsubstack-post-media.s3.amazonaws.com%2Fpublic%2Fimages%2F5d6884f8-2a7a-4431-9ae8-743d2e7e2bf6_1920x1080.jpeg)

Here's the complete guide: [KVM on GitHub](https://github.com/Gr3ytrac3/KVM)
