# -*- bash -*-

#
# Written by: Kr1stj0n C1k0 <kristjoc@ifi.uio.no>
#

build_stack() {

    CMD="cd ../../ && sudo make modules_prepare && sudo make -j32 && sudo make -j32 modules_install && sudo make -j32 headers_install;
         sudo depmod -a;
         sudo find /lib/modules/5.4.0/ -name *.ko -exec strip --strip-unneeded {} +;
         sudo rm -rf /boot/*5.4.0*;
         sudo make -j32 install"
}

build_modules() {
    # SCH_SHQ
    CMD="sudo rmmod -f sch_shq;
         cp Makefile.shq ../../net/sched/Makefile;
         cd ../../ && sudo make modules_prepare && sudo make M=net/sched/ clean && sudo make M=net/sched/ modules && sudo make M=net/sched/ modules_install;
         sudo depmod -a;
         sudo cp /lib/modules/5.4.0/extra/sch_shq.ko /lib/modules/5.4.0/kernel/net/sched/;
         sudo depmod -a;
         cp tools/net_modules/Makefile.sched.init net/sched/Makefile;
         sudo modprobe sch_shq"

    #eval $CMD

    # SCH_RED
    CMD="sudo rmmod -f sch_red;
         cp Makefile.red ../../net/sched/Makefile;
         cd ../../ && sudo make modules_prepare && sudo make M=net/sched/ clean && sudo make M=net/sched/ modules && sudo make M=net/sched/ modules_install;
         sudo depmod -a;
         sudo cp /lib/modules/5.4.0/extra/sch_red.ko /lib/modules/5.4.0/kernel/net/sched/;
         sudo depmod -a;
         cp tools/net_modules/Makefile.sched.init net/sched/Makefile;
         sudo modprobe sch_red"

    #eval $CMD

    # TCP_LGC
    CMD="sudo rmmod -f tcp_lgc;
         cp Makefile.lgc ../../net/ipv4/Makefile;
         cd ../../ && sudo make modules_prepare && sudo make M=net/ipv4/ clean && sudo make M=net/ipv4/ modules && sudo make M=net/ipv4/ modules_install;
         sudo depmod -a;
         sudo cp /lib/modules/5.4.0/extra/tcp_lgc.ko /lib/modules/5.4.0/kernel/net/ipv4/;
         sudo depmod -a;
         cp tools/net_modules/Makefile.ipv4.init net/ipv4/Makefile;
         sudo modprobe tcp_lgc"

    #eval $CMD

    # TCP_DCTCP
    CMD="sudo rmmod -f tcp_dctcp;
         cp Makefile.dctcp ../../net/ipv4/Makefile;
         cd ../../ && sudo make modules_prepare && sudo make M=net/ipv4/ clean && sudo make M=net/ipv4/ modules && sudo make M=net/ipv4/ modules_install;
         sudo depmod -a;
         sudo cp /lib/modules/5.4.0/extra/tcp_dctcp.ko /lib/modules/5.4.0/kernel/net/ipv4/;
         sudo depmod -a;
         cp tools/net_modules/Makefile.ipv4.init net/ipv4/Makefile;
         sudo modprobe tcp_dctcp"

    #eval $CMD
}

#build_stack
#build_modules