
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12417);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-262: pam_smb");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-262");
 script_set_attribute(attribute: "description", value: '
  Updated pam_smb packages are now available which fix a security
  vulnerability (buffer overflow).

  The pam_smb module is a pluggable authentication module (PAM) used to
  authenticate users using an external Server Message Block (SMB) server.

  A buffer overflow vulnerability has been found that affects unpatched
  versions of pam_smb up to and including 1.1.6.

  On systems that use pam_smb and are configured to authenticate a
  remotely accessible service, an attacker can exploit this bug and
  remotely execute arbitrary code. The Common Vulnerabilities and Exposures
  project (cve.mitre.org) has assigned the name CAN-2003-0686 to this issue.

  Red Hat Enterprise Linux contains a version of pam_smb that is vulnerable
  to this issue, however pam_smb is not enabled by default.

  Users of pam_smb are advised to upgrade to these erratum packages, which
  contain a patch to version 1.1.6 to correct this issue.

  Red Hat would like to thank Dave Airlie of the Samba team for notifying us
  of this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-262.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0686");
script_summary(english: "Check for the version of the pam_smb packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"pam_smb-1.1.6-9.7", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
