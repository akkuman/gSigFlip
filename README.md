# gSigFlip

A SigFlip implement in golang, SigFlip is a tool for patching authenticode signed PE files (exe, dll, sys ..etc) in a way that doesn't affect or break the existing authenticode signature, in other words you can change PE file checksum/hash by embedding data (i.e shellcode) without breaking the file signature, integrity checks or PE file functionality.

you can use [SigFlip/Golang](https://github.com/med0x2e/SigFlip/tree/2bc6e9427d48cea9abb8dd0d54201e96922c7240/Golang) to execute the shellcode in the generated file

## Reference
- [github.com/med0x2e/SigFlip](https://github.com/med0x2e/SigFlip)
- [Gamaredon向带有有效签名的PE中嵌入脚本](https://mp.weixin.qq.com/s/bJrEwoq4QkDJvEk_ThvueQ)
