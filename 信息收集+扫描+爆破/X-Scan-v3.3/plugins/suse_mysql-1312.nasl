
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(27356);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  mysql security update (mysql-1312)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch mysql-1312");
 script_set_attribute(attribute: "description", value: "Attackers could read portions of memory by using a user 
name with trailing null byte or via COM_TABLE_DUMP command 
(CVE-2006-1516, CVE-2006-1517).  Attackers could execute 
arbitrary code by causing a buffer overflow via specially 
crafted COM_TABLE_DUMP packets (CVE-2006-1518).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch mysql-1312");
script_end_attributes();

script_cve_id("CVE-2006-1516", "CVE-2006-1517", "CVE-2006-1518");
script_summary(english: "Check for the mysql-1312 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"mysql-5.0.18-16.1", release:"SUSE10.1") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
