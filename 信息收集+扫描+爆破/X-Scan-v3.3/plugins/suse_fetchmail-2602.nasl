
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if (NASL_LEVEL < 3000 ) exit(0);

if(description)
{
 script_id(27213);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  fetchmail: Securityupdate to fix potential man in the middle and denial service attacks. (fetchmail-2602)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch fetchmail-2602");
 script_set_attribute(attribute: "description", value: "Three security issues have been fixed in fetchmail:

CVE-2005-4348: fetchmail when configured for multidrop
mode, allows remote attackers to cause a denial of service
(application crash) by sending messages without headers
from upstream mail servers.

CVE-2006-5867: fetchmail did not properly enforce TLS and
may transmit cleartext passwords over unsecured links if
certain circumstances occur, which allows remote attackers
to obtain sensitive information via man-in-the-middle
(MITM) attacks.

CVE-2006-5974: fetchmail when refusing a message delivered
via the mda option, allowed remote attackers to cause a
denial of service (crash) via unknown vectors that trigger
a NULL pointer dereference when calling the ferror or
fflush functions.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch fetchmail-2602");
script_end_attributes();

script_cve_id("CVE-2005-4348", "CVE-2006-5867", "CVE-2006-5974");
script_summary(english: "Check for the fetchmail-2602 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"fetchmail-6.3.5-23.2", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
