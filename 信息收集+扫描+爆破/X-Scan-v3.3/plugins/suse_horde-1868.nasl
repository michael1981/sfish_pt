
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27265);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  horde: Securityfixes for cross site scripting problems. (horde-1868)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch horde-1868");
 script_set_attribute(attribute: "description", value: "This update fixes the following two security issues in the
Horde Application Framework:
- CVE-2006-3548: Multiple cross-site scripting (XSS)
  vulnerabilities allow remote attackers to inject
  arbitrary web script or HTML via a (1) javascript URI or
  an external (2) http, (3) https, or (4) ftp URI in the
  url parameter in services/go.php (aka the dereferrer),
  (5) a javascript URI in the module parameter in
  services/help (aka the help viewer), and (6) the name
  parameter in services/problem.php (aka the problem
  reporting screen).

- CVE-2006-3549: services/go.php does not properly restrict
  its image proxy capability, which allows remote attackers
  to perform 'Web tunneling' attacks and use the server as
  a proxy via (1) http, (2) https, and (3) ftp URL in the
  url parameter, which is requested from the server.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch horde-1868");
script_end_attributes();

script_cve_id("CVE-2006-3548", "CVE-2006-3549");
script_summary(english: "Check for the horde-1868 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"horde-3.0.9-19.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
