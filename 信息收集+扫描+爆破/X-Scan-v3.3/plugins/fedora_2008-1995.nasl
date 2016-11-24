
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-1995
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(31181);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 8 2008-1995: qemu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-1995 (qemu)");
 script_set_attribute(attribute: "description", value: "QEMU is a generic and open source processor emulator which achieves a good
emulation speed by using dynamic translation. QEMU has two operating modes:

* Full system emulation. In this mode, QEMU emulates a full system (for
example a PC), including a processor and various peripherials. It can be
used to launch different Operating Systems without rebooting the PC or
to debug system code.
* User mode emulation. In this mode, QEMU can launch Linux processes compiled
for one CPU on another CPU.

As QEMU requires no host kernel patches to run, it is safe and easy to use.

-
Update Information:

Ian Jackson discovered that accesses beyond end of qemu emulated disk devices
can result in accesses to emulator's virtual memory space accesses and thus can
allow user with sufficient privilege in guest (root, as this would need
modification to kernel's driver) to break out of VM.    [9]http://marc.info/?l
=debian-security&m=120343592917055&w=2
");
 script_set_attribute(attribute: "risk_factor", value: "High");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

script_summary(english: "Check for the version of the qemu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"qemu-0.9.0-6.fc8", release:"FC8") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
