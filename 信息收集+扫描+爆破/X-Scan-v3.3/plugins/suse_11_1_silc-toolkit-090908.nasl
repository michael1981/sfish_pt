
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41005);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE 11.1 Security Update:  silc-toolkit (2009-09-08)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for silc-toolkit");
 script_set_attribute(attribute: "description", value: "This update of slic-toolkit fixes stack-based overflow
while encoding a ASN.1 OID (CVE-2008-7159) and several
format string bugs (CVE-2009-3051, CVE-2008-7160). The
probability to exploit this issues to execute arbitrary
code is high.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for silc-toolkit");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=535841");
script_end_attributes();

 script_cve_id("CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3051");
script_summary(english: "Check for the silc-toolkit package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"silc-toolkit-1.1.7-7.66.2", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"silc-toolkit-1.1.7-7.66.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"silc-toolkit-devel-1.1.7-7.66.2", release:"SUSE11.1", cpu:"i586") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"silc-toolkit-devel-1.1.7-7.66.2", release:"SUSE11.1", cpu:"x86_64") )
{
	security_warning(port:0, extra:rpm_report_get() );
	exit(0);
}
exit(0,"Host is not affected");
