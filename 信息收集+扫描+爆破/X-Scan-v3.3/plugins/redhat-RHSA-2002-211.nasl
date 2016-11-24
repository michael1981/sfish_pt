#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12325);
 script_version ("$Revision: 1.7 $");
 script_cve_id("CVE-2002-0838");

 script_name(english:"RHSA-2002-211: ggv");
 script_set_attribute(attribute:"synopsis", value:
"The remote host is missing the patch for the advisory RHSA-2002-211");
 
 script_set_attribute(attribute:"description", value:
'
  Updated packages for gv, ggv, and kdegraphics fix a local buffer overflow
  when reading malformed PDF or PostScript files.

  [Updated 07 Jan 2003]
  Added fixed packages for the Itanium (IA64) architecture.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Gv and ggv are user interfaces for the Ghostscript PostScript(R)
  interpreter used to display PostScript and PDF documents on an X Window
  System. KGhostview is the PostScript viewer for the K Desktop Environment.

  Zen Parse found a local buffer overflow in gv version 3.5.8 and earlier.
  An attacker can create a carefully crafted malformed PDF or PostScript file
  in such a way that when that file is viewed arbitrary commands can be
  executed.

  ggv and kghostview contain code derived from gv and therefore have the same
  vulnerability.

  All users of gv, ggv, and kghostview are advised to upgrade to the errata
  packages which contain patches to correct the vulnerability.
');
 script_set_attribute(attribute:"see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-211.html");
 script_set_attribute(attribute:"solution", value: "Get the newest RedHat updates.");
 script_set_attribute(attribute:"cvss_vector", value:"CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
 script_end_attributes();
 
 script_summary(english: "Check for the version of the ggv packages"); 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks"); 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"ggv-1.0.2-5.1", release:"RHEL2.1") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"gv-3.5.8-18.7x", release:"RHEL2.1") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-2.2.2-2.1", release:"RHEL2.1") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"kdegraphics-devel-2.2.2-2.1", release:"RHEL2.1") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host is not affected");
