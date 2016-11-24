
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36414);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:028: cups");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:028 (cups).");
 script_set_attribute(attribute: "description", value: "Security vulnerabilities have been discovered and corrected in CUPS.
CUPS before 1.3.8 allows local users, and possibly remote attackers,
to cause a denial of service (daemon crash) by adding a large number
of RSS Subscriptions, which triggers a NULL pointer dereference
(CVE-2008-5183).
The web interface (cgi-bin/admin.c) in CUPS before 1.3.8 uses the
guest username when a user is not logged on to the web server, which
makes it easier for remote attackers to bypass intended policy and
conduct CSRF attacks via the (1) add and (2) cancel RSS subscription
functions (CVE-2008-5184).
CUPS 1.1.17 through 1.3.9 allows remote attackers to execute arbitrary
code via a PNG image with a large height value, which bypasses a
validation check and triggers a buffer overflow (CVE-2008-5286).
CUPS shipped with Mandriva Linux allows local users to overwrite
arbitrary files via a symlink attack on the /tmp/pdf.log temporary file
(CVE-2009-0032).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:028");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-5183", "CVE-2008-5184", "CVE-2008-5286", "CVE-2009-0032");
script_summary(english: "Check for the version of the cups package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"cups-1.3.6-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.3.6-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.3.6-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.3.6-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.3.6-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cups-1.3.6-1.4mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-1.3.6-5.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-common-1.3.6-5.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"cups-serial-1.3.6-5.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups2-1.3.6-5.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libcups2-devel-1.3.6-5.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cups-1.3.6-5.3mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"cups-", release:"MDK2008.0")
 || rpm_exists(rpm:"cups-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-5183", value:TRUE);
 set_kb_item(name:"CVE-2008-5184", value:TRUE);
 set_kb_item(name:"CVE-2008-5286", value:TRUE);
 set_kb_item(name:"CVE-2009-0032", value:TRUE);
}
exit(0, "Host is not affected");
