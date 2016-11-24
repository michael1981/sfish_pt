
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(39434);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  perl-DBD-Pg: denial of service (perl-DBD-Pg-6227)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch perl-DBD-Pg-6227");
 script_set_attribute(attribute: "description", value: "This update of perl-DBD-Pg fixes a heap-based buffer
overflow in function pg_db_getline() (CVE-2009-0663) and a
denial of service bug that could be triggered remotely
(CVE-2009-1341).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch perl-DBD-Pg-6227");
script_end_attributes();

script_cve_id("CVE-2009-0663", "CVE-2009-1341");
script_summary(english: "Check for the perl-DBD-Pg-6227 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"perl-DBD-Pg-1.49-76.2", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
