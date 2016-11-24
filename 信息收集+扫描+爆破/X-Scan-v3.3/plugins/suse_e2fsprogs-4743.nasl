
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29415);
 script_version ("$Revision: 1.8 $");
 script_name(english: "SuSE Security Update:  Security update for e2fsprogs (e2fsprogs-4743)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch e2fsprogs-4743");
 script_set_attribute(attribute: "description", value: "This update of e2fsprogs fixes several integer overflows in
memory allocating code. Programs that use libext2fs are
therefore vulnerable to memory corruptions that can lead to
arbitrary code execution while loading a specially crafted
image. (CVE-2007-5497)
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
script_set_attribute(attribute: "solution", value: "Install the security patch e2fsprogs-4743");
script_end_attributes();

script_cve_id("CVE-2007-5497");
script_summary(english: "Check for the e2fsprogs-4743 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"e2fsprogs-1.38-25.27", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"e2fsprogs-devel-1.38-25.27", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libcom_err-1.38-25.27", release:"SLES10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"e2fsprogs-1.38-25.27", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"e2fsprogs-devel-1.38-25.27", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
if ( rpm_check( reference:"libcom_err-1.38-25.27", release:"SLED10") )
{
	security_warning(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
