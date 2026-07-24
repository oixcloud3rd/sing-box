---
icon: material/apple
---

# sing-box for Apple platforms

SFI/SFM/SFT allows users to manage and run local or remote sing-box configuration files, and provides
platform-specific function implementation, such as TUN transparent proxy implementation.

## :material-graph: Requirements

* iOS 15.0+ / macOS 13.0+ / Apple tvOS 17.0+
* The distributed iOS package requires a rootless jailbreak on iOS 15.0+

## :material-cellphone-arrow-down: Download (iOS jailbreak version) {#download}

* [GitHub Releases](https://github.com/oixcloud3rd/sing-box/releases) (`SFI-iphoneos-arm64.deb`)

Additional features:

* It can run a [Tailscale SSH server](/configuration/endpoint/tailscale/#ssh_server) on the device.
* [Process matching](/configuration/route/rule/#process_name) (`process_name`, `process_path`, `user`, and so on) works in route and DNS rules.

Other Apple platform versions must be built from source.

## :material-source-repository: Source code

* [GitHub](https://github.com/SagerNet/sing-box-for-apple)
