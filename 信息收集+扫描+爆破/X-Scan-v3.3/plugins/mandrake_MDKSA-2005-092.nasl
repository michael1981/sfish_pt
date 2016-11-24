
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18308);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:092: gzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:092 (gzip).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities have been discovered in the gzip package:
Zgrep in gzip before 1.3.5 does not properly sanitize arguments, which
allows local users to execute arbitrary commands via filenames that are
injected into a sed script. (CVE-2005-0758)
A race condition in gzip 1.2.4, 1.3.3, and earlier when decompressing a
gzip file allows local users to modify permissions of arbitrary files
via a hard link attack on a file while it is being decompressed, whose
permissions are changed by gzip after the decompression is complete.
(CVE-2005-0988)
A directory traversal vulnerability via 'gunzip -N' in gzip 1.2.4
through 1.3.5 allows remote attackers to write to arbitrary directories
via a .. (dot dot) in the original filename within a compressed file.
(CVE-2005-1228)
Updated packages are patched to address these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:092");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-0758", "CVE-2005-0988", "CVE-2005-1228");
script_summary(english: "Check for the version of the gzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gzip-1.2.4a-13.2.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-13.2.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gzip-1.2.4a-14.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gzip-", release:"MDK10.0")
 || rpm_exists(rpm:"gzip-", release:"MDK10.1")
 || rpm_exists(rpm:"gzip-", release:"MDK10.2") )
{
 set_kb_item(name:"CVE-2005-0758", value:TRUE);
 set_kb_item(name:"CVE-2005-0988", value:TRUE);
 set_kb_item(name:"CVE-2005-1228", value:TRUE);
}
exit(0, "Host is not affected");
