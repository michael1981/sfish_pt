
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(36977);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2009:005: xterm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2009:005 (xterm).");
 script_set_attribute(attribute: "description", value: "A vulnerability has been discovered in xterm, which can be exploited
by malicious people to compromise a user's system. The vulnerability
is caused due to xterm not properly processing the DECRQSS Device
Control Request Status String escape sequence. This can be exploited
to inject and execute arbitrary shell commands by e.g. tricking a
user into displaying a malicious text file containing a specially
crafted escape sequence via the more command in xterm (CVE-2008-2383).
The updated packages have been patched to prevent this.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2009:005");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-2383");
script_summary(english: "Check for the version of the xterm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xterm-229-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xterm-232-1.1mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"xterm-236-1.1mdv2009.0", release:"MDK2009.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"xterm-", release:"MDK2008.0")
 || rpm_exists(rpm:"xterm-", release:"MDK2008.1")
 || rpm_exists(rpm:"xterm-", release:"MDK2009.0") )
{
 set_kb_item(name:"CVE-2008-2383", value:TRUE);
}
exit(0, "Host is not affected");
