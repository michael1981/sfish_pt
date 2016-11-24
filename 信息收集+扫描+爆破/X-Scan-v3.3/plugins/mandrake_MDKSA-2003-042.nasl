
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14026);
 script_version ("$Revision: 1.9 $");
 script_name(english: "MDKSA-2003:042-1: sendmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:042-1 (sendmail).");
 script_set_attribute(attribute: "description", value: "Michal Zalweski discovered a vulnerability in sendmail versions earlier
than 8.12.9 in the address parser, which performs insufficient bounds
checking in certain conditions due to a char to int conversion. This
vulnerability makes it poissible for an attacker to take control of
sendmail and is thought to be remotely exploitable, and very likely
locally exploitable. Updated packages are available with patches
applied (the older versions), and the new fixed version is available
for Mandrake Linux 9.1 users.
Update:
The packages for Mandrake Linux 9.1 and 9.1/PPC were not GPG-signed.
This has been fixed and as a result the md5sums have changed. Thanks
to Mark Lyda for pointing this out.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:042-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0161");
script_summary(english: "Check for the version of the sendmail package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sendmail-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-cf-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-devel-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sendmail-doc-8.12.9-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"sendmail-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0161", value:TRUE);
}
exit(0, "Host is not affected");
