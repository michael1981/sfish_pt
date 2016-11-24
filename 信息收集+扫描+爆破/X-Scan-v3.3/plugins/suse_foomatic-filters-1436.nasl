
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27222);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Command injection into foomatic-filters. (foomatic-filters-1436)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch foomatic-filters-1436");
 script_set_attribute(attribute: "description", value: "A Bug in cupsomatic/foomatic-filters that allowed remote 
printer users to execute arbitrary commands as the uid of 
the printer daemon has been fixed (CVE-2004-0801). While 
the same problem was fixed in earlier products, the fix got 
lost during package upgrade of foomatic-filters.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch foomatic-filters-1436");
script_end_attributes();

script_summary(english: "Check for the foomatic-filters-1436 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"foomatic-filters-3.0.2-20.3", release:"SUSE10.1") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
