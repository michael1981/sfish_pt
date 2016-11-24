
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27419);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  This update of rrdtoll fixes a minor denial-of-service problem. (rrdtool-2540)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch rrdtool-2540");
 script_set_attribute(attribute: "description", value: "This update of rrdtool fixes a denial-of-service problem
that occurs when rrdgraph tries to graph data on a
logarithmic scale and the data processed is <= 0.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch rrdtool-2540");
script_end_attributes();

script_summary(english: "Check for the rrdtool-2540 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"rrdtool-1.2.15-38.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
