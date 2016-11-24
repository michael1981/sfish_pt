
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12399);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2003-182: ghostscript");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2003-182");
 script_set_attribute(attribute: "description", value: '
  A ghostscript package fixing a command execution vulnerability is now
  available.

  GNU Ghostscript is an interpreter for the PostScript language, and is often
  used when printing to printers that do not have their own built-in
  PostScript interpreter.

  A flaw has been discovered in the way Ghostscript validates some PostScript
  commands. This flaw allows an attacker to force commands to be executed by
  a print spooler by submitting a malicious print job. Note that using the
  -dSAFER option is not sufficient to prevent command execution.

  Users of Ghostscript are advised to upgrade to these updated packages,
  which are not vulnerable to this issue.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2003-182.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2003-0354");
script_summary(english: "Check for the version of the ghostscript packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ghostscript-6.51-16.3", release:'RHEL2.1') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
