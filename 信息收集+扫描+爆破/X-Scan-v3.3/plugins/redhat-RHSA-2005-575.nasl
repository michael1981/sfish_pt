#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(18657);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0025");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2005-1625", "CVE-2005-1841");
 script_name(english: "RHSA-2005-575: acroread");
 
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2005-575.");
 script_set_attribute(attribute: "description", value:
'  Updated acroread packages that fix a security issue are now available.

  This update has been rated as having critical security impact by the Red
  Hat Security Response Team.

  The Adobe Acrobat Reader browser allows for the viewing, distributing, and
  printing of documents in portable document format (PDF).

  A buffer overflow bug has been found in Adobe Acrobat Reader. It is
  possible to execute arbitrary code on a victim\'s machine if the victim is
  tricked into opening a malicious PDF file. The Common Vulnerabilities and
  Exposures project has assigned the name CVE-2005-1625 to this issue.

  Please note that there is no browser plugin included with the x86_64 Adobe
  Acrobat Reader package; Therefore the security impact of this issue on
  x86_64 is reduced from "critical" to "important".

  Additionally Secunia Research discovered a bug in the way Adobe Acrobat
  Reader creates temporary files. When a user opens a document, temporary
  files are created which may be world readable, allowing a local user to
  view sensitive information. The Common Vulnerabilities and Exposures
  project has assigned the name CVE-2005-1841 to this issue.

  All users of Acrobat Reader are advised to upgrade to these updated
  packages, which contain Acrobat Reader version 7.0.0 and are not vulnerable
  to this issue.');
 script_set_attribute(attribute:"solution", value:
"Get the newest RedHat Updates.");
 script_set_attribute(attribute:"see_also", value: 
"http://rhn.redhat.com/errata/RHSA-2005-575.html");
 script_set_attribute(attribute:"cvss_vector", value:
"CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_end_attributes();
 script_summary(english: "Check for the version of the acroread packages");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"acroread-7.0.0-4.1.0.EL3", release:"RHEL3") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-7.0.0-4.1.0.EL3", release:"RHEL3") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.0-4.2.0.EL4", release:"RHEL4") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"acroread-plugin-7.0.0-4.2.0.EL4", release:"RHEL4") )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}

exit(0, "Host if not affected");
