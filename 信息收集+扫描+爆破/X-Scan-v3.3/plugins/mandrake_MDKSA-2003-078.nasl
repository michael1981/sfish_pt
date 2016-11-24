
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14061);
 script_version ("$Revision: 1.9 $");
 script_bugtraq_id(6629);
 script_name(english: "MDKSA-2003:078: mpg123");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:078 (mpg123).");
 script_set_attribute(attribute: "description", value: "A vulnerability in the mpg123 mp3 player could allow local and/or
remote attackers to cause a DoS and possibly execute arbitrary code via
an mp3 file with a zero bitrate, which causes a negative frame size.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:078");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

 script_cve_id("CVE-2003-0577");
script_summary(english: "Check for the version of the mpg123 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mpg123-0.59r-17.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"mpg123-0.59r-17.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"mpg123-", release:"MDK9.0")
 || rpm_exists(rpm:"mpg123-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0577", value:TRUE);
}
exit(0, "Host is not affected");
