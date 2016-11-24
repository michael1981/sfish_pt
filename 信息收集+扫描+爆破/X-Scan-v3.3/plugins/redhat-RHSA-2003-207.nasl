
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12405);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-207: nfs");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-207");
 script_set_attribute(attribute: "description", value: '
  Updated nfs-utils packages are available that fix a remotely exploitable
  Denial of Service vulnerability.

  The nfs-utils package provides a daemon for the kernel NFS server and
  related tools.

  Janusz Niewiadomski found a buffer overflow bug in nfs-utils version 1.0.3
  and earlier. This bug could be exploited by an attacker, causing a remote
  Denial of Service (crash). It is not believed that this bug could lead to
  remote arbitrary code execution.

  Users are advised to update to these erratum packages, which contain a
  backported security patch supplied by the nfs-utils maintainers and are not
  vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-207.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0252");
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

if ( rpm_check( reference:"nfs-utils-0.3.3-7.21AS", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
