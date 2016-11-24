
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(20107);
 script_version ("$Revision: 1.5 $");
 script_name(english: "RHSA-2005-805: pam");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-805");
 script_set_attribute(attribute: "description", value: '
  An updated pam package that fixes a security weakness is now available for
  Red Hat Enterprise Linux 4.

  This update has been rated as having low security impact by the Red Hat
  Security Response Team.

  PAM (Pluggable Authentication Modules) is a system security tool that
  allows system administrators to set an authentication policy without
  having to recompile programs that handle authentication.

  A bug was found in the way PAM\'s unix_chkpwd helper program validates user
  passwords when SELinux is enabled. Under normal circumstances, it is not
  possible for a local non-root user to verify the password of another local
  user with the unix_chkpwd command. A patch applied that adds SELinux
  functionality makes it possible for a local user to use brute force
  password guessing techniques against other local user accounts. The Common
  Vulnerabilities and Exposures project has assigned the name CVE-2005-2977
  to
  this issue.

  All users of pam should upgrade to this updated package, which contains
  backported patches to correct these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2005-805.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2005-2977");
script_summary(english: "Check for the version of the pam packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pam-0.77-66.13", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"pam-devel-0.77-66.13", release:'RHEL4') )
{
 security_note(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
