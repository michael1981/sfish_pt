
#
# (C) Tenable Network Security, Inc.
#
# This plugin text was extracted from Fedora Security Advisory 2009-2792
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(35962);
 script_version ("$Revision: 1.3 $");
script_name(english: "Fedora 9 2009-2792: evolution-data-server");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory FEDORA-2009-2792 (evolution-data-server)");
 script_set_attribute(attribute: "description", value: "The evolution-data-server package provides a unified backend for programs that
work
with contacts, tasks, and calendar information.

It was originally developed for Evolution (hence the name), but is now used
by other packages.

-
Update Information:

This update fixes two security issues:    Evolution Data Server did not properl
y
check the Secure/Multipurpose Internet Mail Extensions (S/MIME) signatures used
for public key encryption and signing of e-mail messages. An attacker could use
this flaw to spoof a signature by modifying the text of the e-mail message
displayed to the user. (CVE-2009-0547)    It was discovered that Evolution Data
Server did not properly validate NTLM (NT LAN Manager) authentication challenge
packets. A malicious server using NTLM authentication could cause an applicatio
n
using Evolution Data Server to disclose portions of its memory or crash during
user authentication. (CVE-2009-0582)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Get the newest Fedora Updates");
script_end_attributes();

 script_cve_id("CVE-2009-0547", "CVE-2009-0582");
script_summary(english: "Check for the version of the evolution-data-server package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "Fedora Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( rpm_check( reference:"evolution-data-server-2.22.3-3.fc9", release:"FC9") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host is not affected");
