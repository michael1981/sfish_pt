
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29585);
 script_version ("$Revision: 1.6 $");
 script_name(english: "SuSE Security Update:  Security update for tar (tar-2344)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch tar-2344");
 script_set_attribute(attribute: "description", value: "This security update fixes a directory traversal in tar,
where unpacked symlinks could
 be followed outside of the
directory where the tar file is unpacked. (CVE-2006-6097)

The problematic feature has been made optional and is
disabled by default. It can be enabled by a commandline
switch.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch tar-2344");
script_end_attributes();

script_cve_id("CVE-2006-6097");
script_summary(english: "Check for the tar-2344 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"tar-1.15.1-23.5", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"tar-1.15.1-23.5", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
