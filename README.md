# bp

Binary patcher. Takes asm and C as inputs.

Vibe-coded with GPT-5.3 Codex.

## Usage

`bp prepare` generates a patch, and `bp apply` applies the patch.

The following demo will generate `a.out.patch`. The original one prints "Hello, World!\n" whereas the patched one doesn't.

0. Write patch in asm or C
```sh
$ cat example/patch.c
@foo
void newfoo()
{
    return;
}
```

Note that `@` indicates the address to be patched. It can be a symbol and immediate address.  
This simply replaces the target address with the patch contents.

1. Prepare patch
```sh
$ ./bp prepare example/patch.c -o patch.elf -t example/a.out
```

This aggregates multiple patches and generates one `patch.elf`. `objdump -d patch.elf` will show the patch plan, including the addresses to be patched, and the contents.

2. Apply patch
```
./bp apply -p patch.elf -i ./example/a.out -o a.out.patch
```

Done.
