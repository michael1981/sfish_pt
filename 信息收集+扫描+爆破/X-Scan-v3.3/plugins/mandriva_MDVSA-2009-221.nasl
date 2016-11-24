
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(40764);
 script_version("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:221: libneon0.27");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:221 (libneon0.27).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities has been found and corrected in libneon0.27:
neon before 0.28.6, when expat is used, does not properly detect
recursion during entity expansion, which allows context-dependent
attackers to cause a denial of service (memory and CPU consumption)
via a crafted XML document containing a large number of nested entity
references, a similar issue to CVE-2003-1564 (CVE-2009-2473).
neon before 0.28.6, when OpenSSL is used, does not properly handle a
' ' (NUL) character in a domain name in the subject's Common Name
(CN) field of an X.509 certificate, which allows man-in-the-middle
attackers to spoof arbitrary SSL servers via a crafted certificate
issued by a legitimate Certification Authority, a related issue to
CVE-2009-2408 (CVE-2009-2474).
This update provides a solution to these vulnerabilities.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:221");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-1564", "CVE-2009-2408", "CVE-2009-2473", "CVE-2009-2474");
script_summary(english: "Check for the version of the libneon0.27 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libneon0.27-0.28.3-0.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-devel-0.28.3-0.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-static-devel-0.28.3-0.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-0.28.3-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-devel-0.28.3-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-static-devel-0.28.3-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-0.28.3-2.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-devel-0.28.3-2.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libneon0.27-static-devel-0.28.3-2.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"libneon0.27-", release:"MDK2008.1")
 || rpm_exists(rpm:"libneon0.27-", release:"MDK2009.0")
 || rpm_exists(rpm:"libneon0.27-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2003-1564", value:TRUE);
 set_kb_item(name:"CVE-2009-2408", value:TRUE);
 set_kb_item(name:"CVE-2009-2473", value:TRUE);
 set_kb_item(name:"CVE-2009-2474", value:TRUE);
}
exit(0, "Host is not affected");
