
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36890);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:179: metisse");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:179 (metisse).");
 script_set_attribute(attribute: "description", value: "An input validation flaw was found in X.org's MIT-SHM extension.
A client connected to the X.org server could read arbitrary server
memory, resulting in the disclosure of sensitive data of other users
of the X.org server (CVE-2008-1379).
Multiple integer overflows were found in X.org's Render extension.
A malicious authorized client could explot these issues to cause a
denial of service (crash) or possibly execute arbitrary code with
root privileges on the X.org server (CVE-2008-2360, CVE-2008-2361,
CVE-2008-2362).
The Metisse program is likewise affected by these issues; the updated
packages have been patched to prevent them.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:179");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1379", "CVE-2008-2360", "CVE-2008-2361", "CVE-2008-2362");
script_summary(english: "Check for the version of the metisse package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libmetisse1-0.4.0-1.rc4.10.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmetisse1-devel-0.4.0-1.rc4.10.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"metisse-0.4.0-1.rc4.10.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"metisse-fvwm-2.5.20-1.rc4.10.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xmetisse-0.4.0-1.rc4.10.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmetisse1-0.4.0-1.rc4.10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libmetisse1-devel-0.4.0-1.rc4.10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"metisse-0.4.0-1.rc4.10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"metisse-fvwm-2.5.20-1.rc4.10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xmetisse-0.4.0-1.rc4.10.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"metisse-", release:"MDK2008.0")
 || rpm_exists(rpm:"metisse-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-1379", value:TRUE);
 set_kb_item(name:"CVE-2008-2360", value:TRUE);
 set_kb_item(name:"CVE-2008-2361", value:TRUE);
 set_kb_item(name:"CVE-2008-2362", value:TRUE);
}
exit(0, "Host is not affected");
