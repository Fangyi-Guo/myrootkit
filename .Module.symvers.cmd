cmd_/home/carol/Myroot/Module.symvers := sed 's/ko$$/o/' /home/carol/Myroot/modules.order | scripts/mod/modpost -m -a   -o /home/carol/Myroot/Module.symvers -e -i Module.symvers   -T -
