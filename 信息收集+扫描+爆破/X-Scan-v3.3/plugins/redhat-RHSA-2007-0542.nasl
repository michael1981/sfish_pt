
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27830);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-0542: mcstrans");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-0542");
 script_set_attribute(attribute: "description", value: '
  An updated mcstrans package that fixes a security issue and a bug is now
  available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  mcstrans is the translation daemon used on SELinux machines to translate
  program context into human readable form.

  An algorithmic complexity weakness was found in the way the mcstrans daemon
  handled ranges of compartments in sensitivity labels. A local user could
  trigger this flaw causing mctransd to temporarily stop responding to other
  requests; a partial denial of service. (CVE-2007-4570)

  This update also fixes a problem where the mcstrans daemon was preventing
  SSH connections into an SELinux box, that was running a Multi-Level
  Security (MLS) Policy with multiple categories.

  Users of mcstrans are advised to upgrade to this updated package, which
  resolves this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-0542.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-4570");
script_summary(english: "Check for the version of the mcstrans packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"mcstrans-0.2.6-1.el5", release:'RHEL5') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
