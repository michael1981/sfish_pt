
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14127);
 script_version ("$Revision: 1.6 $");
 script_name(english: "MDKSA-2004:028: cvs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:028 (cvs).");
 script_set_attribute(attribute: "description", value: "Sebastian Krahmer from the SUSE security team discovered a remotely
exploitable vulnerability in the CVS client. When doing a cvs checkout
or update over a network, the client accepts absolute pathnames in the
RCS diff files. A maliciously configured server could then create any
file with content on the local user's disk. This problem affects all
versions of CVS prior to 1.11.15 which has fixed the problem.
The updated packages provide 1.11.14 with the pertinent fix for the
problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:028");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-0180");
script_summary(english: "Check for the version of the cvs package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cvs-1.11.14-0.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.14-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cvs-1.11.14-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cvs-", release:"MDK10.0")
 || rpm_exists(rpm:"cvs-", release:"MDK9.1")
 || rpm_exists(rpm:"cvs-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-0180", value:TRUE);
}
exit(0, "Host is not affected");
