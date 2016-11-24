
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27101);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  CASA: Securityfixes for problems found in audit. (CASA-1849)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch CASA-1849");
 script_set_attribute(attribute: "description", value: "Various bugs and problems were fixed in the CASA
authentication framework, some of them security relevant:
- Secrets with special characters inside were handled
  incorrectly.
- Enhanced Salt generation.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch CASA-1849");
script_end_attributes();

script_summary(english: "Check for the CASA-1849 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"CASA-1.6.659-1.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"CASA-32bit-1.6.659-1.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"CASA-64bit-1.6.659-1.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"CASA-devel-1.6.659-1.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"CASA-gui-1.6.659-1.4", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
