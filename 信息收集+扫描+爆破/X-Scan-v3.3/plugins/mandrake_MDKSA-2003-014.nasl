
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13999);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:014: kernel");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:014 (kernel).");
 script_set_attribute(attribute: "description", value: "An updated kernel for 9.0 is available with a number of bug fixes.
Supermount has been completely overhauled and should be solid on all
systems. Other fixes include XFS with high memory, a netfilter fix,
a fix for Sony VAIO DMI, i845 should now work with UDMA, and new
support for VIA C3 is included. Prism24 has been updated so it now
works properly on HP laptops and a new ACPI is included, although it is
disabled by default for broader compatibility.
This also fixes a security problem that allows non-root users to freeze
the kernel, and a fix for a vulnerability in O_DIRECT handling that can
create a limited information leak where any user on the system with
write privilege to the file system from previously deleted files. This
also allows users to create minor file system corruption (this can
easily be repaired by fsck).
For instructions on how to update your kernel, please visit
http://www.mandrakesecure.net/en/kernelupdate.php
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:014");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0018");
script_summary(english: "Check for the version of the kernel package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kernel-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-BOOT-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-doc-2.4.19-24mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-enterprise-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-secure-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-smp-2.4.19.24mdk-1-1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kernel-source-2.4.19-24mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"kernel-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0018", value:TRUE);
}
exit(0, "Host is not affected");
