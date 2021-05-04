# -*- bash -*-

#
# Written by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
#

build_modules() {

    # SCH_SHQ
    CMD="sudo rmmod -f sch_shq;
         cp Makefile.shq ../../net/sched/Makefile;
         cd ../../;
         sudo make modules_prepare;
         sudo make M=../../net/sched/ clean;
         sudo make M=../../net/sched/ modules;
         sudo make M=../../net/sched/ modules_install;
         sudo depmod -a;
         sudo cp /lib/modules/5.4.0/extra/sch_shq.ko /lib/modules/5.4.0/kernel/net/sched/;
         sudo depmod -a;
         cd tools/lgc_shq;
         cp Makefile.shq.init ../../net/sched/Makefile;
         sudo modprobe sch_shq"

    eval $CMD

    # TCP_LGC
    CMD="sudo rmmod -f tcp_lgc;
         cp Makefile.lgc ../../net/ipv4/Makefile;
         cd ../../;
         sudo modules_prepare;
         sudo make M=../../net/ipv4/ clean;
         sudo make M=../../net/ipv4/ modules;
         sudo make M=../../net/ipv4/ modules_install;
         sudo depmod -a;
         sudo cp /lib/modules/5.4.0/extra/tcp_lgc.ko /lib/modules/5.4.0/kernel/net/ipv4/;
         sudo depmod -a;
         cd tools/lgc_shq;
         cp Makefile.lgc.init ../../net/ipv4/Makefile;
         sudo modprobe tcp_lgc"

    # eval $CMD

}

build_modules
