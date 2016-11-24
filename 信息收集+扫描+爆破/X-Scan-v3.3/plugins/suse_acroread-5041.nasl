
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(31296);
 script_version ("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  acroread security and bugfix update (acroread-5041)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch acroread-5041");
 script_set_attribute(attribute: "description", value: "Adobe Acrobat Reader 8.1.2 contained a /tmp race in its
'acroread' wrapper script in the SSL certificate handling.
(CVE-2008-0883)

Furthermore it contained several duplicated copies of
system libraries, which have been removed for this update
to make sure they are up-to-date security wise by using the
system provided ones.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch acroread-5041");
script_end_attributes();

script_cve_id("CVE-2008-0883");
script_summary(english: "Check for the acroread-5041 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"acroread-8.1.2-1.4", release:"SUSE10.3") )
{
	security_note(port:0, extra:rpm_report_get());
	exit(0);
}
exit(0,"Host is not affected");
