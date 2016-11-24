
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(27614);
 script_version ("$Revision: 1.2 $");
 script_name(english: "MDKSA-2007:203: xen");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:203 (xen).");
 script_set_attribute(attribute: "description", value: "Tavis Ormandy discovered a heap overflow flaw during video-to-video
copy operations in the Cirrus VGA extension code that is used in Xen.
A malicious local administrator of a guest domain could potentially
trigger this flaw and execute arbitrary code outside of the domain
(CVE-2007-1320).
Tavis Ormandy also discovered insufficient input validation leading to
a heap overflow in the NE2000 network driver in Xen. If the driver
is in use, a malicious local administrator of a guest domain could
potentially trigger this flaw and execute arbitrary code outside of
the domain (CVE-2007-1321, CVE-2007-5729, CVE-2007-5730).
Steve Kemp found that xen-utils used insecure temporary files within
the xenmon tool that could allow local users to truncate arbitrary
files (CVE-2007-3919).
Joris van Rantwijk discovered a flaw in Pygrub, which is used as a
boot loader for guest domains. A malicious local administrator of
a guest domain could create a carefully-crafted grub.conf file which
could trigger the execution of arbitrary code outside of that domain
(CVE-2007-4993).
Updated packages have been patched to prevent these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:203");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1320", "CVE-2007-1321", "CVE-2007-3919", "CVE-2007-4993", "CVE-2007-5729", "CVE-2007-5730");
script_summary(english: "Check for the version of the xen package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xen-3.0.3-0.20060703.3.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xen-3.0.3-0.20060703.5.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xen-", release:"MDK2007.0")
 || rpm_exists(rpm:"xen-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1320", value:TRUE);
 set_kb_item(name:"CVE-2007-1321", value:TRUE);
 set_kb_item(name:"CVE-2007-3919", value:TRUE);
 set_kb_item(name:"CVE-2007-4993", value:TRUE);
 set_kb_item(name:"CVE-2007-5729", value:TRUE);
 set_kb_item(name:"CVE-2007-5730", value:TRUE);
}
exit(0, "Host is not affected");
