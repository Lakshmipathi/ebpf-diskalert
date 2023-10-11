# ebpf-diskalert

As the name suggests, ebpf-diskalert is a tool designed for monitoring disk usage and triggering actions 
when specific thresholds are exceeded.

Usage
-----

To start using ebpf-diskalert:


`$ sudo ebpf-diskalert -c /path/to/config.toml`

where `config.toml` has following contents

```
devicename = "/dev/sda1"
diskusage_threshold = 90
action = "/path/to/nofity.sh"
repeat_action = 1
```

Here's an explanation of the configuration options:




    - devicename: Specify the device to monitor (e.g., "/dev/sda1").
    - diskusage_threshold: Set the disk usage threshold at which the action should be triggered (e.g., 90%).
    - action: Specify the binary or script to execute when the threshold is breached (e.g., "notify.sh").
    - repeat_action: Define how often the specified action should be repeated. In this example, it is set to 1, meaning the action will execute only once.
      If you set repeat_action = 10, ebpf-diskalert will execute the defined action for every write operation on the "/dev/sda1" device when disk usage surpasses 90%.

Demo
----
In this demonstration, you'll observe that when the disk usage, as indicated by `df -h`, surpasses the specified 20% threshold as defined in `/root/c.toml`, the system automatically runs `lvm_extend.sh` to expand the disk capacity. You can confirm this disk size expansion by monitoring the top-right `df -h /mnt` output as it increases when the usage crosses the 20% threshold.

https://github.com/Lakshmipathi/ebpf-diskalert/assets/624948/57c6924a-1117-4356-af26-d2b67cefc72e


Installation
------------
Download the `ebpf-diskalert` binary from this repo and copy it under `/usr/sbin` Then set appropriate permission. `chmod 500 /usr/sbin/ebpf-diskalert` and run it.

Test Results
------------

Results from different kernel versions listed below. Please note that I didn't have time to explore the failure further, It may be simple bug, please feel free to explore and
send a PR :-) 

| Version   | Result |
|-----------|:------:|
| 5.4.0     | Fail   |
| 5.15.0    | Fail   |
| 5.14.21   | Pass   |
| 6.2.0     | Pass   |
| 6.3.5     | Pass   |
| 6.5.0     | Pass   |
 
  
Reporting bugs:
--------------

To report issues please use [github issue track](https://github.com/lakshmipathi/ebpf-diskalert/issues)
