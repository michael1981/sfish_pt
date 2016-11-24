
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(12312);
 script_version ("$Revision: 1.8 $");
 script_name(english: "RHSA-2002-138: tar");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2002-138");
 script_set_attribute(attribute: "description", value: '
  The unzip and tar utilities contain vulnerabilities which can allow
  arbitrary files to be overwritten during archive extraction.

  The unzip and tar utilities are used for dealing with archives, which
  are multiple files stored inside of a single file.

  A directory traversal vulnerability in unzip version 5.42 and earlier,
  as well as GNU tar 1.13.19 and earlier, allows attackers to overwrite
  arbitrary files during archive extraction via a ".." (dot dot) in an
  extracted filename (CAN-2001-1267, CAN-2001-1268). In addition, unzip
  version 5.42 and earlier also allows attackers to overwrite arbitrary files
  during archive extraction via filenames in the archive that begin with the
  "/" (slash) character (CAN-2001-1269).

  During testing of the fix to GNU tar, we discovered that GNU tar 1.13.25
  was still vulnerable to a modified version of the same problem. Red Hat has
  provided a patch to tar 1.3.25 to correct this problem (CAN-2002-0399).

  Users of unzip and tar are advised to upgrade to these errata packages,
  containing unzip version 5.50 and a patched version of GNU tar 1.13.25,
  which are not vulnerable to these issues.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2002-138.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2001-1267", "CVE-2001-1268", "CVE-2001-1269", "CVE-2002-0399", "CVE-2002-1216");
script_summary(english: "Check for the version of the tar packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"tar-1.13.25-4.AS21.0", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"unzip-5.50-2", release:'RHEL2.1') )
{
 security_warning(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
