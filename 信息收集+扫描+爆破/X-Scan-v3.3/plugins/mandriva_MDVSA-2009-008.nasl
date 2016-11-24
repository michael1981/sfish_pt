
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36993);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:008: qemu");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:008 (qemu).");
 script_set_attribute(attribute: "description", value: "Security vulnerabilities have been discovered and corrected in
VNC server of qemu version 0.9.1 and earlier, which could lead to
denial-of-service attacks (CVE-2008-2382), and make it easier for
remote crackers to guess the VNC password (CVE-2008-5714).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:008");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2382", "CVE-2008-5714");
script_summary(english: "Check for the version of the qemu package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"dkms-kqemu-1.4.0-0.pre1.0.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qemu-0.9.1-0.r5137.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"qemu-img-0.9.1-0.r5137.1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"qemu-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-2382", value:TRUE);
 set_kb_item(name:"CVE-2008-5714", value:TRUE);
}
exit(0, "Host is not affected");
