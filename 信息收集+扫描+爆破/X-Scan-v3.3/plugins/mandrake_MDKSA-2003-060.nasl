
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14043);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:060: LPRng");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:060 (LPRng).");
 script_set_attribute(attribute: "description", value: "Karol Lewandowski discovered a problem with psbanner, a printer filter
that creates a PostScript format banner. psbanner creates a temporary
file for debugging purposes when it is configured as a filter, and does
not check whether or not this file already exists or is a symlink. The
filter will overwrite this file, or the file it is pointing to (if it
is a symlink) with its current environment and called arguments with the
user id that LPRng is running as.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:060");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0136");
script_summary(english: "Check for the version of the LPRng package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"LPRng-3.8.6-2.2mdk", release:"MDK8.2", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"LPRng-3.8.12-2.1mdk", release:"MDK9.0", yank:"mdk") )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"LPRng-", release:"MDK8.2")
 || rpm_exists(rpm:"LPRng-", release:"MDK9.0") )
{
 set_kb_item(name:"CVE-2003-0136", value:TRUE);
}
exit(0, "Host is not affected");
