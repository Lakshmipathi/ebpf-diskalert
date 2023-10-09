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

TBD


Reporting bugs:
--------------

To report issues please use [github issue track](https://github.com/lakshmipathi/ebpf-diskalert/issues)