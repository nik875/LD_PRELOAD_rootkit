conceals wazuh agent process & config files, as well as self. alterations to rootkit files (/etc/ld.so.preload, /usr/local/lib compiled binaries) triggers immediate deletion of rootkit and wazuh-agent.

designed for minimal impact, we can still cd into hidden directories and alter hidden files; the hope is that red team won't try that because they won't know wazuh is even there. realistically they'd only find out when they try inserting their own LD_PRELOAD rootkit, hence apoptosis so they don't find out we did the same.

we'd have to come up with another way of concealing the network traffic and hiding the dashboard website. i have thoughts on this.

run "make install" to compile & insert everything (build-essential, glibc required). tested only on aarch64 ubuntu.
