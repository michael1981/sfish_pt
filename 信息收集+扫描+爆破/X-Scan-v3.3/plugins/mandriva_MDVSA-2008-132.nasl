
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37475);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:132: gnome-screensaver");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:132 (gnome-screensaver).");
 script_set_attribute(attribute: "description", value: "A vulnerability was found in gnome-screensaver prior to 2.22.1
when a remote authentication server was enabled. During a network
outage, gnome-screensaver would crash upon an unlock attempt,
allowing physically local users to gain access to locked sessions
(CVE-2008-0887).
The updated packages have been patched to correct this issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:132");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-0887");
script_summary(english: "Check for the version of the gnome-screensaver package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gnome-screensaver-2.20.0-2.1mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gnome-screensaver-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2008-0887", value:TRUE);
}
exit(0, "Host is not affected");
