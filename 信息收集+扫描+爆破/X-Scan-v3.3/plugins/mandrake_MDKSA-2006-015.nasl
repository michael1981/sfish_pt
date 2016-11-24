
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20794);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:015: hylafax");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:015 (hylafax).");
 script_set_attribute(attribute: "description", value: "Patrice Fournier discovered the faxrcvd/notify scripts
(executed as the uucp/fax user) run user-supplied input through
eval without any attempt at sanitising it first. This would
allow any user who could submit jobs to HylaFAX, or through
telco manipulation control the representation of callid
information presented to HylaFAX to run arbitrary commands as
the uucp/fax user. (CVE-2005-3539, only 'notify' in the covered
versions)
Updated packages were also reviewed for vulnerability to
an issue where if PAM is disabled, a user could log in with no
password. (CVE-2005-3538)
In addition, some fixes to the packages for permissions, and
the %pre/%post scripts were backported from cooker. (#19679)
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:015");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2005-3538", "CVE-2005-3539");
script_summary(english: "Check for the version of the hylafax package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"hylafax-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-1.4.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-3.2.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"MDK10.1")
 || rpm_exists(rpm:"hylafax-", release:"MDK10.2")
 || rpm_exists(rpm:"hylafax-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3538", value:TRUE);
 set_kb_item(name:"CVE-2005-3539", value:TRUE);
}
exit(0, "Host is not affected");
