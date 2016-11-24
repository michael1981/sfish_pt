
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(23797);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2006-0746: mod_auth_kerb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2006-0746");
 script_set_attribute(attribute: "description", value: '
  Updated mod_auth_kerb packages that fix a security flaw and a bug in
  multiple realm handling are now available for Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  mod_auth_kerb is module for the Apache HTTP Server designed to
  provide Kerberos authentication over HTTP.

  An off by one flaw was found in the way mod_auth_kerb handles certain
  Kerberos authentication messages. A remote client could send a specially
  crafted authentication request which could crash an httpd child process
  (CVE-2006-5989).

  A bug in the handling of multiple realms configured using the
  "KrbAuthRealms" directive has also been fixed.

  All users of mod_auth_kerb should upgrade to these updated packages, which
  contain backported patches that resolve these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2006-0746.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2006-5989");
script_summary(english: "Check for the version of the mod_auth_kerb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mod_auth_kerb-5.0-1.3", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
