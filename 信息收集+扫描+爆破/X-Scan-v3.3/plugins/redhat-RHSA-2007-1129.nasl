
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29693);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1129: autofs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1129");
 script_set_attribute(attribute: "description", value: '
  Updated Red Hat Enterprise Linux 4 Technology Preview autofs5 packages are
  now available to fix a security flaw.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The autofs utility controls the operation of the automount daemon, which
  automatically mounts and unmounts file systems after a period of
  inactivity. The autofs version 5 package was made available as a
  technology preview in Red Hat Enterprise Linux version 4.6.

  There was a security issue with the default installed configuration of
  autofs version 5 whereby the entry for the "hosts" map did not specify the
  "nosuid" mount option. A local user with control of a remote nfs server
  could create a setuid root executable within an exported filesystem on the
  remote nfs server that, if mounted using the default hosts map, would allow
  the user to gain root privileges. (CVE-2007-5964)

  Due to the fact that autofs version 5 always mounted hosts map entries suid
  by default, autofs has now been altered to always use the "nosuid" option
  when mounting from the default hosts map. The "suid" option must be
  explicitly given in the master map entry to revert to the old behavior.
  This change affects only the hosts map which corresponds to the /net entry
  in the default configuration.

  Users are advised to upgrade to these updated autofs5 packages, which
  resolve this issue.

  Red Hat would like to thank Josh Lange for reporting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1129.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-5964");
script_summary(english: "Check for the version of the autofs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"autofs5-5.0.1-0.rc2.55.el4_6.1", release:'RHEL4') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
