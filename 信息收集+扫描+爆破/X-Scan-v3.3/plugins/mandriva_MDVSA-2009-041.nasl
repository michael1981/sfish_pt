
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37496);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:041: jhead");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:041 (jhead).");
 script_set_attribute(attribute: "description", value: "Security vulnerabilies have been identified and fixed in jhead.
Buffer overflow in the DoCommand function in jhead before 2.84 might
allow context-dependent attackers to cause a denial of service (crash)
(CVE-2008-4575).
Jhead before 2.84 allows local users to overwrite arbitrary files
via a symlink attack on a temporary file (CVE-2008-4639).
Jhead 2.84 and earlier allows local users to delete arbitrary files
via vectors involving a modified input filename (CVE-2008-4640).
jhead 2.84 and earlier allows attackers to execute arbitrary commands
via shell metacharacters in unspecified input (CVE-2008-4641).
This update provides the latest Jhead to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:041");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-4575", "CVE-2008-4639", "CVE-2008-4640", "CVE-2008-4641");
script_summary(english: "Check for the version of the jhead package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"jhead-2.86-0.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"jhead-2.86-0.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"jhead-2.86-0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"jhead-", release:"MDK2008.0")
 || rpm_exists(rpm:"jhead-", release:"MDK2008.1")
 || rpm_exists(rpm:"jhead-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-4575", value:TRUE);
 set_kb_item(name:"CVE-2008-4639", value:TRUE);
 set_kb_item(name:"CVE-2008-4640", value:TRUE);
 set_kb_item(name:"CVE-2008-4641", value:TRUE);
}
exit(0, "Host is not affected");
