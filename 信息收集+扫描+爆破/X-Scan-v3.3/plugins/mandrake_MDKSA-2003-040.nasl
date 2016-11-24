
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14024);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:040: Eterm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:040 (Eterm).");
 script_set_attribute(attribute: "description", value: "Digital Defense Inc. released a paper detailing insecurities in various
terminal emulators, including Eterm. Many of the features supported by
these programs can be abused when untrusted data is displayed on the
screen. This abuse can be anything from garbage data being displayed
to the screen or a system compromise.
These issues are corrected in Eterm 0.9.2, which is already included in
Mandrake Linux 9.1.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:040");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0021", "CVE-2003-0068");
script_summary(english: "Check for the version of the Eterm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libast1-0.5-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libast1-devel-0.5-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"Eterm-0.9.2-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"Eterm-devel-0.9.2-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"Eterm-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0021", value:TRUE);
 set_kb_item(name:"CVE-2003-0068", value:TRUE);
}
exit(0, "Host is not affected");
