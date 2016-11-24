
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27332);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  libqt4 security update (libqt4-3056)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch libqt4-3056");
 script_set_attribute(attribute: "description", value: "qt wrongly accepts overly long UTF-8 sequences due to a bug
in the UTF-8 decoder. This may lead to security problems
unter certain circumstances. The bug for example allows for
script tag injection in konqueror (CVE-2007-0242).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch libqt4-3056");
script_end_attributes();

script_cve_id("CVE-2007-0242");
script_summary(english: "Check for the libqt4-3056 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"libqt4-4.2.1-20", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libqt4-devel-4.2.1-20", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libqt4-x11-4.2.1-20", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
