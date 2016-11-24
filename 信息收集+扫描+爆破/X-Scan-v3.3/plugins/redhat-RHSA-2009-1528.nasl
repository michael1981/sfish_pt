
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(42285);
 script_version ("$Revision: 1.1 $");
 script_name(english: "RHSA-2009-1528: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-1528");
 script_set_attribute(attribute: "description", value: '
  Updated samba packages that fix a security issue and a bug are now
  available for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A denial of service flaw was found in the Samba smbd daemon. An
  authenticated, remote user could send a specially-crafted response that
  would cause an smbd child process to enter an infinite loop. An
  authenticated, remote user could use this flaw to exhaust system resources
  by opening multiple CIFS sessions. (CVE-2009-2906)

  This update also fixes the following bug:

  * the RHSA-2007:0354 update added code to escape input passed to scripts
  that are run by Samba. This code was missing "c" from the list of valid
  characters, causing it to be escaped. With this update, the previous patch
  has been updated to include "c" in the list of valid characters.
  (BZ#242754)

  Users of Samba should upgrade to these updated packages, which contain a
  backported patch to correct this issue. After installing this update,
  the smb service will be restarted automatically.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-1528.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-2906");
script_summary(english: "Check for the version of the samba packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"samba-3.0.9-1.3E.16", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-3.0.9-1.3E.16", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-3.0.9-1.3E.16", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-3.0.9-1.3E.16", release:'RHEL3') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
