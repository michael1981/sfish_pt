
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29777);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2007-1176: autofs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2007-1176");
 script_set_attribute(attribute: "description", value: '
  Updated autofs packages that fix a security issue are now available for Red
  Hat Enterprise Linux 5.

  This update has been rated as having important security impact by the Red
  Hat Security Response Team.

  The autofs utility controls the operation of the automount daemon, which
  automatically mounts file systems when you use them, and unmounts them when
  you are not using them. This can include network file systems and CD-ROMs.

  There was a security issue with the default configuration of autofs version
  5, whereby the entry for the "-hosts" map did not specify the "nodev" mount
  option. A local user with control of a remote NFS server could create
  special device files on the remote file system, that if mounted using the
  default "-hosts" map, could allow the user to access important system
  devices. (CVE-2007-6285)

  This issue is similar to CVE-2007-5964, which fixed a missing "nosuid"
  mount option in autofs. Both the "nodev" and "nosuid" options should be
  enabled to prevent a possible compromise of machine integrity.

  Due to the fact that autofs always mounted "-hosts" map entries "dev" by
  default, autofs has now been altered to always use the "nodev" option when
  mounting from the default "-hosts" map. The "dev" option must be explicitly
  given in the master map entry to revert to the old behavior. This change
  affects only the "-hosts" map which corresponds to the "/net" entry in the
  default configuration.

  All autofs users are advised to upgrade to these updated packages, which
  resolve this issue.

  Red Hat would like to thank Tim Baum for reporting this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2007-1176.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2007-6285");
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

if ( rpm_check( reference:"autofs-5.0.1-0.rc2.55.el5.2", release:'RHEL5') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
