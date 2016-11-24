
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2008-11593
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37568);
 script_version ("$Revision: 1.2 $");
script_name(english: "Fedora 10 2008-11593: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2008-11593 (kernel)");
 script_set_attribute(attribute: "description", value: "The kernel package contains the Linux kernel (vmlinuz), the core of any
Linux operating system.  The kernel handles the basic functions
of the operating system: memory allocation, process allocation, device
input and output, etc.

-
Update Information:

Update kernel from version 2.6.27.7 to 2.6.27.9:
[9]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.8
[10]http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.27.9    Also incl
udes
three critical fixes scheduled for 2.6.27.10    Update applesmc driver to lates
t
upstream version.  (Adds module autoloading.)    Update ALSA audio drivers to
version 1.0.18a.  (See www.alsa-project.org for details.)    Security fixes:
CVE-2008-5079   in 2.6.27.9  CVE-2008-5182   in 2.6.27.8  CVE-2008-5300   in
2.6.27.8
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2008-5079", "CVE-2008-5182", "CVE-2008-5300");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"kernel-2.6.27.9-159.fc10", prefix:"kernel-", release:"FC10") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
