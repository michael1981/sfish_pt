
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-8929
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(34480);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2008-8929: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-8929 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Update kernel from version 2.6.26.5 to 2.6.26.6:
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.26.6    CVE-2008-3
831
An IOCTL in the i915 driver was not properly restricted to users with the
proper capabilities to use it.    CVE-2008-4410  The vmi_write_ldt_entry
function in arch/x86/kernel/vmi_32.c in the Virtual  Machine Interface (VMI) in
the Linux kernel 2.6.26.5 invokes write_idt_entry  where write_ldt_entry was
intended, which allows local users to cause a  denial of service (persistent
application failure) via crafted function calls,  related to the Java Runtime
Environment (JRE) experiencing improper LDT  selector state, a different
vulnerability than CVE-2008-3247.    CVE-2008-3525  The sbni_ioctl function in
drivers/net/wan/sbni.c in the wan subsystem in  the Linux kernel 2.6.26.3 does
not check for the CAP_NET_ADMIN capability  before processing a (1)
SIOCDEVRESINSTATS, (2) SIOCDEVSHWSTATE, (3)  SIOCDEVENSLAVE, or (4)
SIOCDEVEMANSIPATE ioctl request, which allows local  users to bypass intended
capability restrictions.    CVE-2008-4554  The do_splice_from function in
fs/splice.c in the Linux kernel before 2.6.27  does not reject file descriptors
that have the O_APPEND flag set, which allows  local users to bypass append mod
e
and make arbitrary changes to other locations  in the file.    CVE-2008-4576
sctp in Linux kernel before 2.6.25.18 allows remote attackers to cause a denial
of service (OOPS) via an INIT-ACK that states the peer does not support AUTH,
which causes the sctp_process_init function to clean up active transports and
triggers the OOPS when the T1-Init timer expires.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-3525", "CVE-2008-3831", "CVE-2008-4410", "CVE-2008-4554", "CVE-2008-4576");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.26.6-79.fc9", prefix:"kernel-", release:"FC9") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
