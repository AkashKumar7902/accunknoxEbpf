A demonstration on how to drop TCP packets on a specific port (default: 4040) using ebpf.

**PREREQUISITES**

1. <b>Linux System with eBPF and XDP Support</b>:

    <br>
    A relatively recent Linux kernel (4.18 or later is recommended) that supports eBPF and XDP.
    Kernel headers installed, which are needed for compiling eBPF programs.
    <br>
    <br>

2. <b>Development Tools</b>:
<br>
   
    <b>clang and llvm</b>: Required to compile the eBPF program.
    <b>go</b>: The Go programming language compiler (version 1.18 or later recommended).

<br>

**USAGE**

1. cd into the cmd directory
   ```bash
    cd cmd
   ```
   <br>

2. Run the the ebpf program using 
   ```go
    sudo go run .
   ```
   <br>

3. To test the program, run:
<br>
   
    To verify that TCP packets are being sent and received correctly on the loopback interface. This is useful to ensure that the traffic is indeed being generated as expected.

   ```bash
   sudo tcpdump -i lo port 4040
   ```

   To watch for debug logs to be sure that packets are dropped, run:

   ```bash
   sudo cat  /sys/kernel/debug/tracing/trace_pipe
   ```
   
   To generate traffic, run:

   ```bash
   curl http://localhost:4040
   ```

   You should observe that the curl fails or times out, indicating that the packets are being dropped.

