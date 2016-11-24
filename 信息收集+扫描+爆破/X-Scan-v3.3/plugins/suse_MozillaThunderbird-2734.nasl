
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27129);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  MozillaThunderbird: Securityfix update to 1.5.0.10. (MozillaThunderbird-2734)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch MozillaThunderbird-2734");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Thunderbird to version 1.5.0.10.
It contains stability fixes and some security fixes:

- MFSA 2007-01: As part of the Thunderbird 1.5.0.10 update
  releases several bugs were fixed to improve the stability
  of the browser. Some of these were crashes that showed
  evidence of memory corruption and we presume that with
  enough effort at least some of these could be exploited
  to run arbitrary code. These fixes affected the layout
  engine (CVE-2007-0775), SVG renderer (CVE-2007-0776) and
  javascript engine (CVE-2007-0777).

- MFSA 2007-06: CVE-2007-0008: SSL clients such as Firefox
  and Thunderbird can suffer a buffer overflow if a
  malicious server presents a certificate with a public key
  that is too small to encrypt the entire 'Master Secret'.
  Exploiting this overflow appears to be unreliable but
  possible if the SSLv2 protocol is enabled.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch MozillaThunderbird-2734");
script_end_attributes();

script_cve_id("CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0008");
script_summary(english: "Check for the MozillaThunderbird-2734 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"MozillaThunderbird-1.5.0.10-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"MozillaThunderbird-translations-1.5.0.10-1.1", release:"SUSE10.2") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
