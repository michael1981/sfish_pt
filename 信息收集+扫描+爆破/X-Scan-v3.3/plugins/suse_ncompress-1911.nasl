
#
# (C) Tenable Network Security
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(29527);
 script_version ("$Revision: 1.5 $");
 script_name(english: "SuSE Security Update:  Security update for ncompress (ncompress-1911)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing the security patch ncompress-1911");
 script_set_attribute(attribute: "description", value: "Lack of bounds checking in the decompression routine could
result in a heap buffer underflow. Attackers could
potentially exploit this to execute arbitrary code by
tricking users into decompressing a specially crafted
archive (CVE-2006-1168).
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_set_attribute(attribute: "solution", value: "Install the security patch ncompress-1911");
script_end_attributes();

script_cve_id("CVE-2006-1168");
script_summary(english: "Check for the ncompress-1911 package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");

if ( rpm_check( reference:"ncompress-4.2.4-15.5", release:"SLES10") )
{
	security_hole(port:0, extra:rpm_report_get());
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
