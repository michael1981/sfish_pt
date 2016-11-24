
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35947);
 script_version ("$Revision: 1.4 $");
 script_name(english: "RHSA-2009-0358: evolution");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2009-0358");
 script_set_attribute(attribute: "description", value: '
  Updated evolution packages that fixes multiple security issues are now
  available for Red Hat Enterprise Linux 3.

  This update has been rated as having moderate security impact by the Red
  Hat Security Response Team.

  Evolution is the integrated collection of e-mail, calendaring, contact
  management, communications, and personal information management (PIM) tools
  for the GNOME desktop environment.

  It was discovered that evolution did not properly validate NTLM (NT LAN
  Manager) authentication challenge packets. A malicious server using NTLM
  authentication could cause evolution to disclose portions of its memory or
  crash during user authentication. (CVE-2009-0582)

  An integer overflow flaw which could cause heap-based buffer overflow was
  found in the Base64 encoding routine used by evolution. This could cause
  evolution to crash, or, possibly, execute an arbitrary code when large
  untrusted data blocks were Base64-encoded. (CVE-2009-0587)

  All users of evolution are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  instances of evolution must be restarted for the update to take effect.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2009-0358.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2009-0582", "CVE-2009-0587");
script_summary(english: "Check for the version of the evolution packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"evolution-1.4.5-25.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"evolution-devel-1.4.5-25.el3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
