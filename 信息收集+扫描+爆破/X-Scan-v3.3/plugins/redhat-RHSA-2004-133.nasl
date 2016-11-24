
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12481);
 script_version ("$Revision: 1.7 $");
 script_name(english: "RHSA-2004-133: squid");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-133");
 script_set_attribute(attribute: "description", value: '
  An updated squid package is avaliable that fixes a security vulnerability
  in
  URL decoding and provides a new ACL type for protecting vulnerable clients.

  Squid is a full-featured Web proxy cache.

  A bug was found in the processing of %-encoded characters in a URL in
  versions of Squid 2.5.STABLE4 and earlier. If a Squid configuration uses
  Access Control Lists (ACLs), a remote attacker could create URLs that would
  not be correctly tested against Squid\'s ACLs, potentially allowing clients
  to access prohibited URLs.

  Users of Squid should update to these erratum packages which are not
  vulnerable to this issue.

  In addition, these packages contain a new Access Control type, "urllogin",
  which can be used to protect vulnerable Microsoft Internet Explorer clients
  from accessing URLs that contain login information. Such URLs are often
  used by fraudsters to trick web users into revealing valuable personal
  data.

  Note that the default Squid configuration does not make use of this new
  access control type. You must explicitly configure Squid with ACLs that
  use this new type, in accordance with your own site policies.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-133.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0189");
script_summary(english: "Check for the version of the squid packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"squid-2.4.STABLE6-10.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"squid-2.5.STABLE3-5.3E", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
