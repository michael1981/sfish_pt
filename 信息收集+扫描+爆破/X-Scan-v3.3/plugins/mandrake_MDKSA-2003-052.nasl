
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14036);
 script_version ("$Revision: 1.8 $");
 script_name(english: "MDKSA-2003:052: snort");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:052 (snort).");
 script_set_attribute(attribute: "description", value: "An integer overflow was discovered in the Snort stream4 preprocessor
by the Sourcefire Vulnerability Research Team. This preprocessor
(spp_stream4) incorrectly calculates segment size parameters during
stream reassembly for certainm sequence number ranges. This can
lead to an integer overflow that can in turn lead to a heap overflow
that can be exploited to perform a denial of service (DoS) or even
remote command excution on the host running Snort.
Disabling the stream4 preprocessor will make Snort invulnerable to
this attack, and the flaw has been fixed upstream in Snort version
2.0. Snort versions 1.8 through 1.9.1 are vulnerable.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:052");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0209");
script_summary(english: "Check for the version of the snort package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"snort-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql+flexresp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-2.0.0-2.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql+flexresp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-2.0.0-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-bloat-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-mysql+flexresp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-mysql-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-plain+flexresp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql+flexresp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-postgresql-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-snmp+flexresp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"snort-snmp-2.0.0-2.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"snort-", release:"MDK8.2")
 || rpm_exists(rpm:"snort-", release:"MDK9.0")
 || rpm_exists(rpm:"snort-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0209", value:TRUE);
}
exit(0, "Host is not affected");
