cmd_/home/carol/Myroot/modules.order := {   echo /home/carol/Myroot/rootkit.ko; :; } | awk '!x[$$0]++' - > /home/carol/Myroot/modules.order
