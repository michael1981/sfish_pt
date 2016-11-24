#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12421);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0020");
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695");

 script_name(english:"RHSA-2003-280: openssh");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2003-280");
 
 script_set_attribute(attribute:"description", value:
'
  Updated OpenSSH packages are now available that fix bugs that may be
  remotely exploitable.

  [Updated 17 Sep 2003]
  Updated packages are now available to fix additional buffer manipulation
  problems which were fixed in OpenSSH 3.7.1. The Common Vulnerabilities and
  Exposures project (cve.mitre.org) has assigned the name CVE-2003-0695 to
  these additional issues.

  We have also included fixes from Solar Designer for some additional memory
  bugs. The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0682 to these issues.

  OpenSSH is a suite of network connectivity tools that can be used to
  establish encrypted connections between systems on a network and can
  provide interactive login sessions and port forwarding, among other
  functions.

  The OpenSSH team has announced a bug which affects the OpenSSH buffer
  handling code. This bug has the potential of being remotely exploitable.
  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2003-0693 to this issue.

  All users of OpenSSH should immediately apply this update which contains a
  backported fix for this issue.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-280.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the openssh packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"openssh-3.1p1-14", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-3.1p1-14", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-askpass-gnome-3.1p1-14", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-clients-3.1p1-14", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"openssh-server-3.1p1-14", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
