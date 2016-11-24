
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27409);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  This update fixes a possible SSL man-in-the-middle attack (python-wbem-2692)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch python-wbem-2692");
 script_set_attribute(attribute: "description", value: "This update switches the usage from python's SSL class to
python-openssl. The original python class does not verify
the SSL certificates which makes python-wbem vulnerable to
a man-in-the-middle attack.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch python-wbem-2692");
script_end_attributes();

script_summary(english: "Check for the python-wbem-2692 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"python-wbem-0.4.cvs20060406-7.3", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
