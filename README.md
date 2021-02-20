# darkCON ret2csu talk

1. [slides](https://slides.com/aneeshdogra-1/ret2csu)
2. [talk video](https://www.youtube.com/watch?v=yHQkuGOrau4)

# Sample problem

abc.c in the repo.

# Exploit 1: ret2libc without ASLR 
- compiled using `gcc -no-pie -fno-stack-protector abc.c -o abc`
- ASLR disabled `echo 0 | sudo tee proc/sys/kernel/randomize_va_space`
# Exploit 2: ret2plt
compiled using `gcc -no-pie -fno-stack-protector abc.c -o abc`
# Exploit 3: ret2csu
compiled using `gcc -no-pie -fno-stack-protector abc.c -o abc`
