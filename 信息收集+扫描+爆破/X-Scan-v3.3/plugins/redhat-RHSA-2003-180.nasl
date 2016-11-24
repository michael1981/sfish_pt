#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12398);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0178");

 script_name(english:"RHSA-2003-180: sharutils");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2003-180");
 
 script_set_attribute(attribute:"description", value:
'
  Updated packages for sharutils which fix potential privilege escalation
  using the uudecode utility are available.

  The sharutils package contains a set of tools for encoding and decoding
  packages of files in binary or text format.

  The uudecode utility creates an output file without checking to see if
  it was about to write to a symlink or a pipe. If a user uses uudecode to
  extract data into open shared directories, such as /tmp, this vulnerability
  could be used by a local attacker to overwrite files or lead to privilege
  escalation.

  The Common Vulnerabilities and Exposures project (cve.mitre.org) has
  assigned the name CVE-2002-0178 to this issue.

  Users are advised to upgrade to these errata sharutils packages which
  contain a version of uudecode that has been patched to check for an
  existing pipe or symlink output file.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-180.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the sharutils packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"sharutils-4.2.1-8.7.x", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
