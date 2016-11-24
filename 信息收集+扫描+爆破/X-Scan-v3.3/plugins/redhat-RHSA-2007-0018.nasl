
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(24316);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2007-0018: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0018");
 script_set_attribute(attribute: "description", value: '
  Updated fetchmail packages that fix two security issues are now available.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Fetchmail is a remote mail retrieval and forwarding utility.

  A denial of service flaw was found when Fetchmail was run in multidrop
  mode. A malicious mail server could send a message without headers which
  would cause Fetchmail to crash (CVE-2005-4348). This issue did not affect
  the version of Fetchmail shipped with Red Hat Enterprise Linux 2.1 or 3.

  A flaw was found in the way Fetchmail used TLS encryption to connect to
  remote hosts. Fetchmail provided no way to enforce the use of TLS
  encryption and would not authenticate POP3 protocol connections properly
  (CVE-2006-5867). This update corrects this issue by enforcing TLS
  encryption when the "sslproto" configuration directive is set to "tls1".

  Users of Fetchmail should update to these packages, which contain
  backported patches to correct these issues.

  Note: This update may break configurations which assumed that Fetchmail
  would use plain-text authentication if TLS encryption is not supported by
  the POP3 server even if the "sslproto" directive is set to "tls1". If you
  are using a custom configuration that depended on this behavior you will
  need to modify your configuration appropriately after installing this update.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0018.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-4348", "CVE-2006-5867");
script_summary(english: "Check for the version of the fetchmail packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"fetchmail-5.9.0-21.7.3.el2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.0-21.7.3.el2.1.4", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.0-3.el3.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmail-6.2.5-6.el4.5", release:'RHEL4') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
