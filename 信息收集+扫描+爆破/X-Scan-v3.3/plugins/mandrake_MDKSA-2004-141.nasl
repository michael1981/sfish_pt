
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15839);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2004:141: zip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:141 (zip).");
 script_set_attribute(attribute: "description", value: "A vulnerability in zip was discovered where zip would not check the
resulting path length when doing recursive folder compression, which
could allow a malicious person to convince a user to create an archive
containing a specially-crafted path name. By doing so, arbitrary code
could be executed with the permissions of the user running zip.
The updated packages are patched to prevent this problem.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:141");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2004-1010");
script_summary(english: "Check for the version of the zip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"zip-2.3-11.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zip-2.3-11.1.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"zip-2.3-11.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"zip-", release:"MDK10.0")
 || rpm_exists(rpm:"zip-", release:"MDK10.1")
 || rpm_exists(rpm:"zip-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2004-1010", value:TRUE);
}
exit(0, "Host is not affected");
