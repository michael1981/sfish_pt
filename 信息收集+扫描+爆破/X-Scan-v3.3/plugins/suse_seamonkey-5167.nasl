
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(32027);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  seamonkey: Security update (seamonkey-5167)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch seamonkey-5167");
 script_set_attribute(attribute: "description", value: "This update brings Mozilla Seamonkey to the level of
seamonkey security update version 1.1.9

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
script_set_attribute(attribute: "solution", value: "Install the security patch seamonkey-5167");
script_end_attributes();

script_cve_id("CVE-2008-1241", "CVE-2008-1195", "CVE-2008-1240", "CVE-2007-4879", "CVE-2008-1238", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235");
script_summary(english: "Check for the seamonkey-5167 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"seamonkey-1.0.9-1.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-calendar-1.0.9-1.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-dom-inspector-1.0.9-1.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-irc-1.0.9-1.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-mail-1.0.9-1.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-spellchecker-1.0.9-1.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"seamonkey-venkman-1.0.9-1.12", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
