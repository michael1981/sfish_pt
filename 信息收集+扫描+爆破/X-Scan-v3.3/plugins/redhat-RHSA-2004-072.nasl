
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12470);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-072: nfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-072");
 script_set_attribute(attribute: "description", value: '
  Updated nfs-utils packages that fix a flaw leading to possible rpc.mountd
  crashes are now available.

  The nfs-utils package contains the rpc.mountd program, which implements the
  NFS mount protocol.

  A flaw was discovered in versions of rpc.mountd in nfs-utils versions after
  1.0.3 and prior to 1.0.6. When mounting a directory, rpc.mountd could
  crash if the reverse lookup of the client in DNS failed to match the
  forward lookup. An attacker who has the ability to mount remote
  directories from a server could make use of this flaw to cause a denial of
  service by making rpc.mountd crash.

  Users are advised to upgrade to these updated packages, which contain
  nfs-utils 1.0.6 and is not vulnerable to this issue.

  NOTE: Red Hat Enterprise Linux 2.1 includes a version of rpc.mountd that is
  not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-072.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0154");
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

if ( rpm_check( reference:"nfs-utils-1.0.6-7.EL", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
