
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14032);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:048: eog");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:048 (eog).");
 script_set_attribute(attribute: "description", value: "A vulnerability was discovered in the Eye of GNOME (EOG) program,
version 2.2.0 and earlier, that is used for displaying graphics. A
carefully crafted filename passed to eog could lead to the execution
of arbitrary code as the user executing eog.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:048");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0165");
script_summary(english: "Check for the version of the eog package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"eog-1.0.2-1.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"eog-2.2.0-1.1mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"eog-", release:"MDK9.0")
 || rpm_exists(rpm:"eog-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0165", value:TRUE);
}
exit(0, "Host is not affected");
