
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14056);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2003:073-1: unzip");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:073-1 (unzip).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in unzip 5.50 and earlier that allows
attackers to overwrite arbitrary files during archive extraction by
placing non-printable characters between two '.' characters. These
invalid characters are filtered which results in a '..' sequence.
The patch applied to these packages prevents unzip from writing to
parent directories unless the '-:' command line option is used.
Update:
Ben Laurie found that the original patch used to fix this issue missed
a case where the path component included a quoted slash. An updated
patch was used to build these packages.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:073-1");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0282");
script_summary(english: "Check for the version of the unzip package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"unzip-5.50-4.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-4.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-4.2mdk", release:"MDK9.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"unzip-", release:"MDK8.2")
 || rpm_exists(rpm:"unzip-", release:"MDK9.0")
 || rpm_exists(rpm:"unzip-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0282", value:TRUE);
}
exit(0, "Host is not affected");
