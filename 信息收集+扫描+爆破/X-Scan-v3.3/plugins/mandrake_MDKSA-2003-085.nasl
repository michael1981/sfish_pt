
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14067);
 script_version ("$Revision: 1.7 $");
 script_name(english: "MDKSA-2003:085: gdm");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2003:085 (gdm).");
 script_set_attribute(attribute: "description", value: "Several vulnerabilities were discovered in versions of gdm prior to
2.4.1.6. The first vulnerability is that any user can read any text
file on the system due to code originally written to be run as the user
logging in was in fact being run as the root user. This code is what
allows the examination of the ~/.xsession-errors file. If a user makes
a symlink from this file to any other file on the system during the
session and ensures that the session lasts less than ten seconds, the
user can read the file provided it was readable as a text file.
Another two vulnerabilities were found in the XDMCP code that could be
exploited to crash the main gdm daemon which would inhibit starting
any new sessions (although the current session would be unaffected).
The first problem here is due to the indirect query structure being
used right after being freed due to a missing 'continue' statement in a
loop; this happens if a choice of server expired and the client tried
to connect.
The second XDMCP problem is that when authorization data is being
checked as a string, the length is not checked first. If the data is
less than 18 bytes long, the daemon may wander off the end of the
string a few bytes in the strncmp which could cause a SEGV.
These updated packages bring gdm to version 2.4.1.6 which is not
vulnerable to any of these problems. Also note that XDMCP support is
disabled by default in gdm.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:085");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2003-0547", "CVE-2003-0548", "CVE-2003-0549");
script_summary(english: "Check for the version of the gdm package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"gdm-2.4.1.6-0.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.1.6-0.2mdk", release:"MDK9.0", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdm-2.4.1.6-0.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gdm-Xnest-2.4.1.6-0.3mdk", release:"MDK9.1", yank:"mdk") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"gdm-", release:"MDK9.0")
 || rpm_exists(rpm:"gdm-", release:"MDK9.1") )
{
 set_kb_item(name:"CVE-2003-0547", value:TRUE);
 set_kb_item(name:"CVE-2003-0548", value:TRUE);
 set_kb_item(name:"CVE-2003-0549", value:TRUE);
}
exit(0, "Host is not affected");
