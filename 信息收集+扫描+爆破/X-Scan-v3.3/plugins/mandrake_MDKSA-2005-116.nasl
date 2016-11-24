
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18678);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2005:116-1: cpio");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:116-1 (cpio).");
 script_set_attribute(attribute: "description", value: "A race condition has been found in cpio 2.6 and earlier which allows
local users to modify permissions of arbitrary files via a hard link
attack on a file while it is being decompressed, whose permissions are
changed by cpio after the decompression is complete (CVE-2005-1111).
A vulnerability has been discovered in cpio that allows a malicious
cpio file to extract to an arbitrary directory of the attackers
choice. cpio will extract to the path specified in the cpio file,
this path can be absolute (CVE-2005-1229).
Update:
The previous packages had a problem upgrading due to an unresolved
issue with tar and rmt. These packages correct the problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:116-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-1111", "CVE-2005-1229");
script_summary(english: "Check for the version of the cpio package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cpio-2.5-4.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cpio-2.5-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cpio-2.6-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cpio-", release:"MDK10.0")
 || rpm_exists(rpm:"cpio-", release:"MDK10.1")
 || rpm_exists(rpm:"cpio-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-1111", value:TRUE);
 set_kb_item(name:"CVE-2005-1229", value:TRUE);
}
exit(0, "Host is not affected");
