
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);

if(description)
{
 script_id(41452);
 script_version("$Revision: 1.2 $");
 script_name(english: "SuSE Security Update:  ruby (2009-07-03)");
 script_set_attribute(attribute: "synopsis", value: 
"The remote SuSE system is missing a security patch for ruby");
 script_set_attribute(attribute: "description", value: "This ruby update improves return value checks for openssl
function OCSP_basic_verify() (CVE-2009-0642) which allowed
an attacker to use revoked certificates.

The entropy of DNS identifiers was increased
(CVE-2008-3905) to avaid spoofing attacks.

The code for parsing XML data was vulnerable to a denial of
service bug (CVE-2008-3790).

An attack on algorithm complexity was possible in function
WEBrick::HTTP::DefaultFileHandler() while parsing HTTP
requests (CVE-2008-3656) as well as by using the regex
engine (CVE-2008-3443) causing high CPU load.

Ruby's access restriction code (CVE-2008-3655) as well as
safe-level handling using function DL.dlopen()
(CVE-2008-3657) and big decimal handling (CVE-2009-1904)
was improved.

Bypassing HTTP basic authentication
(authenticate_with_http_digest) is not possible anymore.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "solution", value: "Run yast to install the security patch for ruby");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=499253");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=478019");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=423234");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=420084");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=415678");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=511568");
script_set_attribute(attribute: "see_also", value: "https://bugzilla.novell.com/show_bug.cgi?id=509914");
script_end_attributes();

 script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905", "CVE-2009-0642", "CVE-2009-1904");
script_summary(english: "Check for the ruby package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security, Inc.");
 script_family(english: "SuSE Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/SuSE/rpm-list") ) exit(1, "Could not gather the list of packages");
if ( rpm_check( reference:"ruby-1.8.7.p72-5.22.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ruby-doc-html-1.8.7.p72-5.22.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.7.p72-5.22.1", release:"SLES11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
if ( rpm_check( reference:"ruby-1.8.7.p72-5.22.1", release:"SLED11", cpu:"i586") )
{
	security_hole(port:0, extra:rpm_report_get() );
	exit(0);
}
# END OF TEST
exit(0,"Host is not affected");
