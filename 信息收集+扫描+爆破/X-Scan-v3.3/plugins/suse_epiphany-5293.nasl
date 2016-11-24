
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(33121);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  mozilla-xulrunner181: Update to 1.8.1.14 (epiphany-5293)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch epiphany-5293");
 script_set_attribute(attribute: "description", value: "mozilla-xulrunner181 was updated to version 1.8.1.14,
fixing various bugs including 1 security bug:

+ MFSA 2008-20/CVE-2008-1380: Crash in JavaScript garbage
  collector
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch epiphany-5293");
script_end_attributes();

script_cve_id("CVE-2008-1380");
script_summary(english: "Check for the epiphany-5293 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"epiphany-2.20.0-8.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-devel-2.20.0-8.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-doc-2.20.0-8.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"epiphany-extensions-2.20.0-8.4", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner181-1.8.1.14-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner181-32bit-1.8.1.14-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner181-64bit-1.8.1.14-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner181-devel-1.8.1.14-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"mozilla-xulrunner181-l10n-1.8.1.14-0.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
