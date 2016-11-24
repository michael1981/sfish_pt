
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14102);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2004:002: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2004:002 (ethereal).");
 script_set_attribute(attribute: "description", value: "Two vulnerabilities were discovered in versions of Ethereal prior to
0.10.0 that can be exploited to make Ethereal crash by injecting
malformed packets onto the wire or by convincing a user to read a
malformed packet trace file. The first vulnerability is in the SMB
dissector and the second is in the Q.391 dissector. It is not known
whether or not these issues could lead to the execution of arbitrary
code.
The updated packages provide Ethereal 0.10.0 which is not vulnerable
to these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:002");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-1012", "CVE-2003-1013");
script_summary(english: "Check for the version of the ethereal package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ethereal-0.10.0a-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ethereal-0.10.0a-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1")
 || rpm_exists(rpm:"ethereal-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-1012", value:TRUE);
 set_kb_item(name:"CVE-2003-1013", value:TRUE);
}
exit(0, "Host is not affected");
