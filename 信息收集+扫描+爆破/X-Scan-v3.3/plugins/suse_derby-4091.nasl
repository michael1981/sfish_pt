
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(28224);
 script_version ("$Revision: 1.3 $");
 script_name(english: "SuSE Security Update:  derby: Fixed remote denial of service (derby-4091)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch derby-4091");
 script_set_attribute(attribute: "description", value: "Apache Derby did not determine schema privilege
requirements during the DropSchemaNode bind phase, which
allows remote authenticated users to execute arbitrary drop
schema statements in SQL authorization mode. (CVE-2006-7217)

This update also brings a new requirement of a Java 1.5 JRE.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch derby-4091");
script_end_attributes();

script_cve_id("CVE-2006-7217");
script_summary(english: "Check for the derby-4091 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"derby-10.3.1.4-0.1", release:"SUSE10.2") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
