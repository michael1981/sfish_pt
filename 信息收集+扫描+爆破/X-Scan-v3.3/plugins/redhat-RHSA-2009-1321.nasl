
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40838);
 script_version ("$Revision: 1.2 $");
 script_name(english: "RHSA-2009-1321: nfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1321");
 script_set_attribute(attribute: "description", value: '
  An updated nfs-utils package that fixes a security issue and several bugs
  is now available.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  The nfs-utils package provides a daemon for the kernel NFS server and
  related tools.

  It was discovered that nfs-utils did not use tcp_wrappers correctly.
  Certain hosts access rules defined in "/etc/hosts.allow" and
  "/etc/hosts.deny" may not have been honored, possibly allowing remote
  attackers to bypass intended access restrictions. (CVE-2008-4552)

  This updated package also fixes the following bugs:

  * the "LOCKD_TCPPORT" and "LOCKD_UDPPORT" options in "/etc/sysconfig/nfs"
  were not honored: the lockd daemon continued to use random ports. With this
  update, these options are honored. (BZ#434795)

  * it was not possible to mount NFS file systems from a system that has
  the "/etc/" directory mounted on a read-only file system (this could occur
  on systems with an NFS-mounted root file system). With this update, it is
  possible to mount NFS file systems from a system that has "/etc/" mounted
  on a read-only file system. (BZ#450646)

  * arguments specified by "STATDARG=" in "/etc/sysconfig/nfs" were removed
  by the nfslock init script, meaning the arguments specified were never
  passed to rpc.statd. With this update, the nfslock init script no longer
  removes these arguments. (BZ#459591)

  * when mounting an NFS file system from a host not specified in the NFS
  server\'s "/etc/exports" file, a misleading "unknown host" error was logged
  on the server (the hostname lookup did not fail). With this update, a
  clearer error message is provided for these situations. (BZ#463578)

  * the nhfsstone benchmark utility did not work with NFS version 3 and 4.
  This update adds support to nhfsstone for NFS version 3 and 4. The new
  nhfsstone "-2", "-3", and "-4" options are used to select an NFS version
  (similar to nfsstat(8)). (BZ#465933)

  * the exportfs(8) manual page contained a spelling mistake, "djando", in
  the EXAMPLES section. (BZ#474848)

  * in some situations the NFS server incorrectly refused mounts to hosts
  that had a host alias in a NIS netgroup. (BZ#478952)

  * in some situations the NFS client used its cache, rather than using
  the latest version of a file or directory from a given export. This update
  adds a new mount option, "lookupcache=", which allows the NFS client to
  control how it caches files and directories. Note: The Red Hat Enterprise
  Linux 5.4 kernel update (the fourth regular update) must be installed in
  order to use the "lookupcache=" option. Also, "lookupcache=" is currently
  only available for NFS version 3. Support for NFS version 4 may be
  introduced in future Red Hat Enterprise Linux 5 updates. Refer to Red Hat
  Bugzilla #511312 for further information. (BZ#489335)

  Users of nfs-utils should upgrade to this updated package, which contains
  backported patches to correct these issues. After installing this update,
  the nfs service will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1321.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2008-4552");
script_summary(english: "Check for the version of the nfs packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"nfs-utils-1.0.9-42.el5", release:'RHEL5') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
