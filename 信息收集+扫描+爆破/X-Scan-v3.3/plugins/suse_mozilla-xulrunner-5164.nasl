
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31991);
 script_version ("$Revision: 1.10 $");
 script_name(english: "SuSE Security Update:  Security update for epiphany (mozilla-xulrunner-5164)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mozilla-xulrunner-5164");
 script_set_attribute(attribute: "description", value: "This update fixes security issues also fixes in the Mozilla
Firefox 2.0.0.13 update round.

Following security problems were fixed:
- MFSA 2008-19/CVE-2008-1241: XUL popup spoofing variant
  (cross-tab popups)
- MFSA 2008-18/CVE-2008-1195 and CVE-2008-1240: Java socket
  connection to any local port via LiveConnect
- MFSA 2008-17/CVE-2007-4879: Privacy issue with SSL Client
  Authentication
- MFSA 2008-16/CVE-2008-1238: HTTP Referrer spoofing with
  malformed URLs
- MFSA 2008-15/CVE-2008-1236 and CVE-2008-1237: Crashes
  with evidence of memory corruption (rv:1.8.1.13)
- MFSA 2008-14/CVE-2008-1233, CVE-2008-1234, and
  CVE-2008-1235: JavaScript privilege escalation and
  arbitrary code execution.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch mozilla-xulrunner-5164");
script_end_attributes();

script_cve_id("CVE-2007-4879", "CVE-2008-1195", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
script_summary(english: "Check for the mozilla-xulrunner-5164 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"mozilla-xulrunner-1.8.0.14eol-0.5", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-1.8.5-14.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-devel-1.8.5-14.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-doc-1.8.5-14.6", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"gecko-sdk-1.8.0.14eol-0.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner-1.8.0.14eol-0.5", release:"SLED10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
