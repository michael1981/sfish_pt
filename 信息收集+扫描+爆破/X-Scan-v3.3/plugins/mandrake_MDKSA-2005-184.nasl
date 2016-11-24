
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20043);
 script_version ("$Revision: 1.5 $");
 script_name(english: "MDKSA-2005:184: cfengine");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2005:184 (cfengine).");
 script_set_attribute(attribute: "description", value: "Javier Fern ndez-Sanguino Pe a discovered several insecure temporary
file uses in cfengine <= 1.6.5 and <= 2.1.16 which allows local users
to overwrite arbitrary files via a symlink attack on temporary files
used by vicf.in. (CVE-2005-2960)
In addition, Javier discovered the cfmailfilter and cfcron.in files
for cfengine <= 1.6.5 allow local users to overwrite arbitrary files
via a symlink attack on temporary files (CVE-2005-3137)
The updated packages have been patched to address this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:184");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-2960", "CVE-2005-3137");
script_summary(english: "Check for the version of the cfengine package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cfengine-1.6.5-4.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cfengine-2.1.12-7.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfservd-2.1.12-7.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cfengine-base-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfagent-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfenvd-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfexecd-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cfengine-cfservd-2.1.15-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cfengine-", release:"MDK10.1")
 || rpm_exists(rpm:"cfengine-", release:"MDK10.2")
 || rpm_exists(rpm:"cfengine-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-2960", value:TRUE);
 set_kb_item(name:"CVE-2005-3137", value:TRUE);
}
exit(0, "Host is not affected");
