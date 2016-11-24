
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35647);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  sbl: fixed buffer overflow (CVE-2009-0310) (sbl-5992)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch sbl-5992");
 script_set_attribute(attribute: "description", value: "A buffer overflow in the sbl package has been fixed.
Incoming data and authentication-strings have not been
checked properly. CVE-2009-0310 has been assigned to this
issue.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch sbl-5992");
script_end_attributes();

script_cve_id("CVE-2009-0310");
script_summary(english: "Check for the sbl-5992 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"sbl-3.0f-16.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
