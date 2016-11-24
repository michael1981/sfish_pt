
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2007-1785
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27734);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 7 2007-1785: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2007-1785 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system:  memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Update to kernel 2.6.22.2, 2.6.22.3 and 2.6.22.4:
[8]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.2
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.3
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.22.4

- Fix failure to find serial ports on some machines.
- Detect broken timers on some AMD dual-core machines: fixes
hangs and failure to boot.
- Don't crash when a userspace driver requests too much memory.
- Update the CFS scheduler to more closely match upstream.
- Wireless driver update.
- Enable ACPI_DEBUG in -debug builds.
- Fix e820 memory hole sizing on x86_64.
- Add four bugfixes for sky2 ethernet.
- Fix some SCSI async scanning bugs.
- Fix polling in r8169 driver.
- Fix wrong sensor values with some chips.

CVE-2007-3848:
Linux kernel 2.4.35 and other versions allows local users to
send arbitrary signals to a child process that is running at
higher privileges by causing a setuid-root parent process to
die, which delivers an attacker-controlled parent process
death signal (PR_SET_PDEATHSIG).

");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2007-3848");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.22.4-65.fc7", prefix:"kernel-", release:"FC7") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
