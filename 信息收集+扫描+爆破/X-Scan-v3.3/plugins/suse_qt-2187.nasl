
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29561);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for Qt (qt-2187)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch qt-2187");
 script_set_attribute(attribute: "description", value: "Multiple integer overflows have been found in image
processing functions within the QT library. These could
potentially lead to heap overflows and code execution.
(CVE-2006-4811)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch qt-2187");
script_end_attributes();

script_cve_id("CVE-2006-4811");
script_summary(english: "Check for the qt-2187 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"qt-4.1.0-29.7", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
