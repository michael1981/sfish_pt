
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12419);
 script_version ("$Revision: 1.10 $");
 script_name(english: "RHSA-2003-270: kdebase");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-270");
 script_set_attribute(attribute: "description", value: '
  Updated KDE packages that resolve a local security issue with KDM PAM
  support and weak session cookie generation are now available.

  KDE is a graphical desktop environment for the X Window System.

  KDE between versions 2.2.0 and 3.1.3 inclusive contain a bug in the KDE
  Display Manager (KDM) when checking the result of a pam_setcred() call.
  If an error condition is triggered by the installed PAM modules, KDM might
  grant local root access to any user with valid login credentials.

  It has been reported that one way to trigger this bug is by having a
  certain configuration of the MIT pam_krb5 module that leaves a session
  alive and gives root access to a regular user. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2003-0690
  to this issue.

  In addition, the session cookie generation algorithm used by KDM was
  considered too weak to supply a full 128 bits of entropy. This could make
  it possible for non-authorized users, who are able to bypass any host
  restrictions, to brute-force the session cookie and gain acess to the
  current session. The Common Vulnerabilities and Exposures project
  (cve.mitre.org) has assigned the name CAN-2003-0692 to this issue.

  Users of KDE are advised to upgrade to these erratum packages, which
  contain security patches correcting these issues.

  Red Hat would like to thank the KDE team for notifying us of this issue and
  providing the security patches.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-270.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0690", "CVE-2003-0692");
script_summary(english: "Check for the version of the kdebase packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"kdebase-2.2.2-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdebase-devel-2.2.2-11", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
