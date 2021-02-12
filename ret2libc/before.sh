# disable aslr 
echo "Disabling ASLR"
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# verify libc base
./abc < /dev/null&
cat /proc/`ps aux | grep abc |  awk '{print $2}' | head -1`/maps | grep libc

