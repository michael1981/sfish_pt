#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12324);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0836");

 script_name(english:"RHSA-2002-195: tetex");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2002-195");
 
 script_set_attribute(attribute:"description", value:
'
  Updated packages for dvips are available which fix a vulnerability allowing
  print users to execute arbitrary commands.

  [Updated 13 Aug 2003]
  Added tetex-doc package that was originally left out of the errata.

  The dvips utility converts DVI format into PostScript(TM), and is used in
  Red Hat Linux as a print filter for printing DVI files. A vulnerability
  has been found in dvips which uses the system() function insecurely when
  managing fonts.

  Since dvips is used in a print filter, this allows local or remote
  attackers who have print access to carefully craft a print job that allows
  them to execute arbitrary code as the user \'lp\'.

  A work around for this vulnerability is to remove the print filter for DVI
  files. The following commands, run as root, will accomplish this:

  rm -f /usr/share/printconf/mf_rules/mf40-tetex_filters
  rm -f /usr/lib/rhs/rhs-printfilters/dvi-to-ps.fpi

  However, to fix the problem in the dvips utility as well as remove the
  print filter we recommend that all users upgrade to the these packages
  contained within this erratum which contain a patch for this issue.

  This vulnerability was discovered by Olaf Kirch of SuSE.

  Additionally, the file /var/lib/texmf/ls-R had world-writable permissions.

  This issue is also fixed by the packages contained within this erratum.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-195.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the tetex packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"tetex-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-afm-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-doc-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvilj-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-dvips-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-fonts-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-latex-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"tetex-xdvi-1.0.7-38.4", release:"RHEL2.1") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
