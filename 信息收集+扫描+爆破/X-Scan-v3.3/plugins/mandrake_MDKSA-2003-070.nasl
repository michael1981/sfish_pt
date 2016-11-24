
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14053);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:070: ethereal");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:070 (ethereal).");
 script_set_attribute(attribute: "description", value: "A number of string handling bugs were found in the packet dissectors in
ethereal that can be exploited using specially crafted packets to cause
ethereal to consume excessive amounts of memory, crash, or even execute
arbitray code.
These vulnerabilities have been fixed upsteam in ethereal 0.9.13 and
all users are encouraged to upgrade.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:070");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0428", "CVE-2003-0429", "CVE-2003-0431", "CVE-2003-0432");
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

if ( rpm_check( reference:"ethereal-0.9.13-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ethereal-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0428", value:TRUE);
 set_kb_item(name:"CVE-2003-0429", value:TRUE);
 set_kb_item(name:"CVE-2003-0431", value:TRUE);
 set_kb_item(name:"CVE-2003-0432", value:TRUE);
}
exit(0, "Host is not affected");
