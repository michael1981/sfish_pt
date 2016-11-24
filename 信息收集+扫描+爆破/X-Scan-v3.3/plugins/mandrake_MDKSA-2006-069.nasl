
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(21206);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2006:069: openvpn");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2006:069 (openvpn).");
 script_set_attribute(attribute: "description", value: "A vulnerability in OpenVPN 2.0 through 2.0.5 allows a malicious server
to execute arbitrary code on the client by using setenv with the
LD_PRELOAD environment variable.
Updated packages have been patched to correct this issue by removing
setenv support.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2006:069");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2006-1629");
script_summary(english: "Check for the version of the openvpn package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"openvpn-2.0.1-2.2.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"openvpn-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2006-1629", value:TRUE);
}
exit(0, "Host is not affected");
