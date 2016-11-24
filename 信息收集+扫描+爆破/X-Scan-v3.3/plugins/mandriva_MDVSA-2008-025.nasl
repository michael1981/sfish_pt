
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37710);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:025: x11-server-xgl");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:025 (x11-server-xgl).");
 script_set_attribute(attribute: "description", value: "An input validation flaw was found in the X.org server's XFree86-Misc
extension that could allow a malicious authorized client to cause
a denial of service (crash), or potentially execute arbitrary code
with root privileges on the X.org server (CVE-2007-5760).
A flaw was found in the X.org server's XC-SECURITY extension that
could allow a local user to verify the existence of an arbitrary file,
even in directories that are not normally accessible to that user
(CVE-2007-5958).
A memory corruption flaw was found in the X.org server's XInput
extension that could allow a malicious authorized client to cause a
denial of service (crash) or potentially execute arbitrary code with
root privileges on the X.org server (CVE-2007-6427).
An information disclosure flaw was found in the X.org server's TOG-CUP
extension that could allow a malicious authorized client to cause
a denial of service (crash) or potentially view arbitrary memory
content within the X.org server's address space (CVE-2007-6428).
Two integer overflow flaws were found in the X.org server's EVI and
MIT-SHM modules that could allow a malicious authorized client to
cause a denial of service (crash) or potentially execute arbitrary
code with the privileges of the X.org server (CVE-2007-6429).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:025");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-5760", "CVE-2007-5958", "CVE-2007-6427", "CVE-2007-6428", "CVE-2007-6429");
script_summary(english: "Check for the version of the x11-server-xgl package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"x11-server-xgl-0.0.1-0.20060714.11.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xgl-0.0.1-0.20070105.4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"x11-server-xgl-0.0.1-0.20070917.2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"x11-server-xgl-", release:"MDK2007.0")
 || rpm_exists(rpm:"x11-server-xgl-", release:"MDK2007.1")
 || rpm_exists(rpm:"x11-server-xgl-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2007-5760", value:TRUE);
 set_kb_item(name:"CVE-2007-5958", value:TRUE);
 set_kb_item(name:"CVE-2007-6427", value:TRUE);
 set_kb_item(name:"CVE-2007-6428", value:TRUE);
 set_kb_item(name:"CVE-2007-6429", value:TRUE);
}
exit(0, "Host is not affected");
