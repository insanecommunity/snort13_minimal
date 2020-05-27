# The minimum version of snort 1.3

To run it
```bash
sudo ./build/snort -l 1,3,5,7 -w af:00.0,mprq_en=1   --socket-mem=6144 -n 4 -- -p 0x01 -c myrule
```
