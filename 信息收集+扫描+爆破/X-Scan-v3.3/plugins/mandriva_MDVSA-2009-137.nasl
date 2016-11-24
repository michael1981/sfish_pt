
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(39478);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:137: java-1.6.0-openjdk");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:137 (java-1.6.0-openjdk).");
 script_set_attribute(attribute: "description", value: "Multiple security vulnerabilities has been identified and fixed in
Little cms library embedded in OpenJDK:
A memory leak flaw allows remote attackers to cause a denial of service
(memory consumption and application crash) via a crafted image file
(CVE-2009-0581).
Multiple integer overflows allow remote attackers to execute arbitrary
code via a crafted image file that triggers a heap-based buffer
overflow (CVE-2009-0723).
Multiple stack-based buffer overflows allow remote attackers to
execute arbitrary code via a crafted image file associated with a large
integer value for the (1) input or (2) output channel (CVE-2009-0733).
A flaw in the transformations of monochrome profiles allows remote
attackers to cause denial of service triggered by a NULL pointer
dereference via a crafted image file (CVE-2009-0793).
Further security fixes in the JRE and in the Java API of OpenJDK:
A flaw in handling temporary font files by the Java Virtual
Machine (JVM) allows remote attackers to cause denial of service
(CVE-2006-2426).
An integer overflow flaw was found in Pulse-Java when handling Pulse
audio source data lines. An attacker could use this flaw to cause an
applet to crash, leading to a denial of service (CVE-2009-0794).
A flaw in Java Runtime Environment initialized LDAP connections
allows authenticated remote users to cause denial of service on the
LDAP service (CVE-2009-1093).
A flaw in the Java Runtime Environment LDAP client in handling server
LDAP responses allows remote attackers to execute arbitrary code on
the client side via malicious server response (CVE-2009-1094).
Buffer overflows in the the Java Runtime Environment unpack200 utility
allow remote attackers to execute arbitrary code via an crafted applet
(CVE-2009-1095, CVE-2009-1096).
A buffer overflow in the splash screen processing allows a attackers
to execute arbitrary code (CVE-2009-1097).
A buffer overflow in GIF images handling allows remote attackers to
execute arbitrary code via an crafted GIF image (CVE-2009-1098).
A flaw in the Java API for XML Web Services (JAX-WS) service endpoint
handling allows remote attackers to cause a denial of service on the
service endpoint's server side (CVE-2009-1101).
A flaw in the Java Runtime Environment Virtual Machine code generation
allows remote attackers to execute arbitrary code via a crafted applet
(CVE-2009-1102).
This update provides fixes for these issues.
Update:
java-1.6.0-openjdk requires rhino packages and these has been further
updated.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:137");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-2426", "CVE-2009-0581", "CVE-2009-0723", "CVE-2009-0733", "CVE-2009-0793", "CVE-2009-0794", "CVE-2009-1093", "CVE-2009-1094", "CVE-2009-1095", "CVE-2009-1096", "CVE-2009-1097", "CVE-2009-1098", "CVE-2009-1101", "CVE-2009-1102");
script_summary(english: "Check for the version of the java-1.6.0-openjdk package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.2mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-demo-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-javadoc-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-manual-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-demo-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-javadoc-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-manual-1.7-0.0.2.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-1.6.0.0-0.20.b16.0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-demo-1.6.0.0-0.20.b16.0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-devel-1.6.0.0-0.20.b16.0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-0.20.b16.0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-plugin-1.6.0.0-0.20.b16.0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"java-1.6.0-openjdk-src-1.6.0.0-0.20.b16.0.2mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-demo-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-javadoc-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-manual-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-demo-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-javadoc-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"rhino-manual-1.7-0.0.3.1mdv2009.1", release:"MDK2009.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"java-1.6.0-openjdk-", release:"MDK2009.0")
 || rpm_exists(rpm:"java-1.6.0-openjdk-", release:"MDK2009.1") )
{
 set_kb_item(name:"CVE-2006-2426", value:TRUE);
 set_kb_item(name:"CVE-2009-0581", value:TRUE);
 set_kb_item(name:"CVE-2009-0723", value:TRUE);
 set_kb_item(name:"CVE-2009-0733", value:TRUE);
 set_kb_item(name:"CVE-2009-0793", value:TRUE);
 set_kb_item(name:"CVE-2009-0794", value:TRUE);
 set_kb_item(name:"CVE-2009-1093", value:TRUE);
 set_kb_item(name:"CVE-2009-1094", value:TRUE);
 set_kb_item(name:"CVE-2009-1095", value:TRUE);
 set_kb_item(name:"CVE-2009-1096", value:TRUE);
 set_kb_item(name:"CVE-2009-1097", value:TRUE);
 set_kb_item(name:"CVE-2009-1098", value:TRUE);
 set_kb_item(name:"CVE-2009-1101", value:TRUE);
 set_kb_item(name:"CVE-2009-1102", value:TRUE);
}
exit(0, "Host is not affected");
