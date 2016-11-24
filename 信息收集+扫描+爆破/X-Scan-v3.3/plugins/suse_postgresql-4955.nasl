
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(30251);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  postgresql security update (postgresql-4955)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch postgresql-4955");
 script_set_attribute(attribute: "description", value: "This version update to 8.2.6 fixes among other things
several security issues:
- Index Functions Privilege Escalation: CVE-2007-6600
- Regular Expression Denial-of-Service: CVE-2007-4772,
  CVE-2007-6067, CVE-2007-4769
- DBLink Privilege Escalation: CVE-2007-6601
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch postgresql-4955");
script_end_attributes();

script_cve_id("CVE-2007-6600", "CVE-2007-4772", "CVE-2007-6067", "CVE-2007-4769", "CVE-2007-6601");
script_summary(english: "Check for the postgresql-4955 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"postgresql-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-contrib-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-devel-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-docs-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-libs-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-libs-32bit-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-libs-64bit-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-plperl-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-plpython-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-pltcl-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"postgresql-server-8.2.6-0.1", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
