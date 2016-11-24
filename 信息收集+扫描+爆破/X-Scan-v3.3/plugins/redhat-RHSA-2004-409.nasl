
#
# (C) Tenable Network Security
#
# The text of this plugin is (C) Red Hat Inc.
#

include("compat.inc");
if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(13853);
 script_version ("$Revision: 1.9 $");
 script_name(english: "RHSA-2004-409: sox");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory RHSA-2004-409");
 script_set_attribute(attribute: "description", value: '
  Updated sox packages that fix buffer overflows in the WAV file handling
  code are now available.

  SoX (Sound eXchange) is a sound file format converter. SoX can convert
  between many different digitized sound formats and perform simple sound
  manipulation functions, including sound effects.

  Buffer overflows existed in the parsing of WAV file header fields. It was
  possible that a malicious WAV file could have caused arbitrary code to be
  executed when the file was played or converted. The Common Vulnerabilities
  and Exposures project (cve.mitre.org) has assigned the name CAN-2004-0557
  to these issues.

  All users of sox should upgrade to these updated packages, which resolve
  these issues as well as fix a number of minor bugs.


');
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://rhn.redhat.com/errata/RHSA-2004-409.html");
script_set_attribute(attribute: "solution", value: "Get the newest RedHat Updates.");
script_end_attributes();

script_cve_id("CVE-2004-0557");
script_summary(english: "Check for the version of the sox packages");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Red Hat Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/RedHat/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"sox-12.17.4-4.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"sox-devel-12.17.4-4.3", release:'RHEL3') )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
exit(0, "Host if not affected");
