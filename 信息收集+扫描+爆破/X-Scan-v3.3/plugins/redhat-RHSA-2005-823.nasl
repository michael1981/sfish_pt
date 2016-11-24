
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20106);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-823: fetchmail");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-823");
 script_set_attribute(attribute: "description", value: '
  Updated fetchmail packages that fix insecure configuration file creation is
  now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  Fetchmail is a remote mail retrieval and forwarding utility.

  A bug was found in the way the fetchmailconf utility program writes
  configuration files. The default behavior of fetchmailconf is to write a
  configuration file which may be world readable for a short period of time.
  This configuration file could provide passwords to a local malicious
  attacker within the short window before fetchmailconf sets secure
  permissions. The Common Vulnerabilities and Exposures project has assigned
  the name CVE-2005-3088 to this issue.

  Users of fetchmail are advised to upgrade to these updated packages, which
  contain a backported patch which resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-823.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-3088");
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

if ( rpm_check( reference:"fetchmail-5.9.0-21.7.3.el2.1.2", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"fetchmailconf-5.9.0-21.7.3.el2.1.2", release:'RHEL2.1') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
