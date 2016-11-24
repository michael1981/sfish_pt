
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12393);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-161: xinetd");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-161");
 script_set_attribute(attribute: "description", value: '
  Updated xinetd packages fix a security vulnerability and other bugs.

  Xinetd is a master server that is used to to accept service
  connection requests and start the appropriate servers.

  Because of a programming error, memory was allocated and never freed if a
  connection was refused for any reason. An attacker could exploit this flaw
  to crash the xinetd server, rendering all services it controls unavaliable.

  In addition, other flaws in xinetd could cause incorrect operation in
  certain unusual server configurations.

  All users of xinetd are advised to update to the packages listed in this
  erratum, which contain an upgrade to xinetd-2.3.11 and are not vulnerable
  to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-161.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0211");
script_summary(english: "Check for the version of the xinetd packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"xinetd-2.3.11-2.AS2.1", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
