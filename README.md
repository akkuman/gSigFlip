# gSigFlip

A SigFlip implement in golang, SigFlip is a tool for patching authenticode signed PE files (exe, dll, sys ..etc) in a way that doesn't affect or break the existing authenticode signature, in other words you can change PE file checksum/hash by embedding data (i.e shellcode) without breaking the file signature, integrity checks or PE file functionality.

you can use [SigFlip/Golang](https://github.com/med0x2e/SigFlip/tree/2bc6e9427d48cea9abb8dd0d54201e96922c7240/Golang) to execute the shellcode in the generated file

## Usage

```shell
Usage of gSigFlip.exe:
  -out string
        output pe file path (default "out.exe")
  -pe string
        pe file path which you want ot hide data
  -sf string
        the path of the file where shellcode is stored
  -tag string
        the tag you want to use, support "\x1a \xdf" "\x1a\xdf" "1a, df" "1a df" (default "fe ed fa ce fe ed fa ce")
  -xor string
        the xor key you want to use
```

## As a Package

Please view [cmd/gSigFlip/main.go](cmd/gSigFlip/main.go)

## Reference

- [github.com/med0x2e/SigFlip](https://github.com/med0x2e/SigFlip)
- [Gamaredon向带有有效签名的PE中嵌入脚本](https://mp.weixin.qq.com/s/bJrEwoq4QkDJvEk_ThvueQ)
