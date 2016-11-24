
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12379);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2003-096: samba");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-096");
 script_set_attribute(attribute: "description", value: '
  Updated Samba packages are now available to fix security vulnerabilities
  found during a code audit.

  Samba is a suite of utilities which provides file and printer sharing
  services to SMB/CIFS clients.

  Sebastian Krahmer discovered a security vulnerability present
  in unpatched versions of Samba prior to 2.2.8. An anonymous user could use
  the vulnerability to gain root access on the target machine.

  Additionally, a race condition could allow an attacker to overwrite
  critical system files.

  All users of Samba are advised to update to the erratum packages which
  contain patches to correct these vulnerabilities.

  These packages contain the security fixes backported to the Samba 2.2.7
  codebase.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-096.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0085", "CVE-2003-0086", "CVE-2003-1332");
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

if ( rpm_check( reference:"samba-2.2.7-2.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.2.7-2.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.2.7-2.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"samba-swat-2.2.7-2.21as", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
