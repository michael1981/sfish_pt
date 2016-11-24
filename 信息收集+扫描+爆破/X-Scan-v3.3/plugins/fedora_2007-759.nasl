
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-759
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(29285);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 6 2007-759: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-759 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

Update Information:

Update to Linux 2.6.22.14:
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.10
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.11
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.12
[11]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.13
[12]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.14

CVE-2007-5501:
The tcp_sacktag_write_queue function in net/ipv4/tcp_input.c
in Linux kernel 2.6.24-rc2 and earlier allows remote
attackers to cause a denial of service (crash) via crafted
ACK responses that trigger a NULL pointer dereference.

CVE-2007-5500:
The wait_task_stopped function in the Linux kernel before
2.6.23.8 checks a TASK_TRACED bit instead of an exit_state
value, which allows local users to cause a denial of service
(machine crash) via unspecified vectors.

Plus:
Fix compat class device links in sysfs.
Fix boot speed when virtualized on Intel VT processors.
Fix ppc64 vDSO DWARF info for CR register (#350291)

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-5500", "CVE-2007-5501");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.22.14-72.fc6", prefix:"kernel-", release:"FC6") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
