
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-9044
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40780);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 11 2009-9044: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-9044 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Security fixes:  - CVE-2009-2691: Information disclosure in proc filesystem  -
CVE-2009-2848: execve: must clear current->child_tid  - CVE-2009-2849: md: null
pointer dereference  - CVE-2009-2847: Information leak in do_sigaltstack
Restore missing LIRC drivers, dropped in previous release.    Backport upstream
fixes that further improve the security of mmap of low addresses.
(CVE-2009-2695)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-1895", "CVE-2009-1897", "CVE-2009-2407", "CVE-2009-2691", "CVE-2009-2692", "CVE-2009-2695", "CVE-2009-2767", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2849");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.29.6-217.2.16.fc11", prefix:"kernel-", release:"FC11") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
