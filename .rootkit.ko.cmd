cmd_/home/carol/Myroot/rootkit.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000  --build-id=sha1  -T ./scripts/module-common.lds -o /home/carol/Myroot/rootkit.ko /home/carol/Myroot/rootkit.o /home/carol/Myroot/rootkit.mod.o;  true