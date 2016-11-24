
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(35646);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  netatalk: papd daemon allowed arbitrary shell command execution (netatalk-5989)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch netatalk-5989");
 script_set_attribute(attribute: "description", value: "This update of netatalk adds a filter for characters of
user-supplied data to papd. Prior to this update it was
possible to execute arbitrary shell commands remotely.
(CVE-2008-5718)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "solution", value: "Install the security patch netatalk-5989");
script_end_attributes();

script_cve_id("CVE-2008-5718");
script_summary(english: "Check for the netatalk-5989 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"netatalk-2.0.3-130.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"netatalk-devel-2.0.3-130.3", release:"SUSE10.3") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
