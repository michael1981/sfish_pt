
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(40022);
 script_version("$Revision: 1.4 $");
 script_name(english: "SuSE 11.0 Security Update:  libapr-util1 (2009-06-08)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for libapr-util1");
 script_set_attribute(attribute: "description", value: "This update of libapr-util1 fixes a memory consumption bug
in the XML parser that can cause a remote denial-of-service
vulnerability in applications using APR (WebDAV for
example) (CVE-2009-1955). Additionally a one byte buffer
overflow in function apr_brigade_vprintf() (CVE-2009-1956)
and buffer underflow in function apr_strmatch_precompile()
(CVE-2009-0023) was fixed too. Depending on the application
using this function it can lead to remote denial of service
or information leakage.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for libapr-util1");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=509825");
script_end_attributes();

 script_cve_id("CVE-2009-0023", "CVE-2009-1955", "CVE-2009-1956");
script_summary(english: "Check for the libapr-util1 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libapr-util1-1.2.12-43.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-1.2.12-43.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-dbd-mysql-1.2.12-43.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-dbd-mysql-1.2.12-43.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-dbd-pgsql-1.2.12-43.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-dbd-pgsql-1.2.12-43.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-dbd-sqlite3-1.2.12-43.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-dbd-sqlite3-1.2.12-43.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-devel-1.2.12-43.2", release:"SUSE11.0", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"libapr-util1-devel-1.2.12-43.2", release:"SUSE11.0", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
