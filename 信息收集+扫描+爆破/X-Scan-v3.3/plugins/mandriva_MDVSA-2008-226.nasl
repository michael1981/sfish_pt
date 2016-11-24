
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(38018);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:226: ruby");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:226 (ruby).");
 script_set_attribute(attribute: "description", value: "A denial of service condition was found in Ruby's regular expression
engine. If a Ruby script tried to process a large amount of data
via a regular expression, it could cause Ruby to enter an infinite
loop and crash (CVE-2008-3443).
A number of flaws were found in Ruby that could allow an attacker to
create a carefully crafted script that could allow for the bypass of
certain safe-level restrictions (CVE-2008-3655).
A denial of service vulnerability was found in Ruby's HTTP server
toolkit, WEBrick. A remote attacker could send a specially-crafted
HTTP request to a WEBrick server that would cause it to use an
excessive amount of CPU time (CVE-2008-3656).
An insufficient taintness check issue was found in Ruby's DL module,
a module that provides direct access to the C language functions.
This flaw could be used by an attacker to bypass intended safe-level
restrictions by calling external C functions with the arguments from
an untrusted tainted input (CVE-2008-3657).
A denial of service condition in Ruby's XML document parsing module
(REXML) could cause a Ruby application using the REXML module to use
an excessive amount of CPU and memory via XML documents with large
XML entitity definitions recursion (CVE-2008-3790).
The Ruby DNS resolver library used predictable transaction IDs and
a fixed source port when sending DNS requests. This could be used
by a remote attacker to spoof a malicious reply to a DNS query
(CVE-2008-3905).
The updated packages have been patched to correct these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:226");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-3443", "CVE-2008-3655", "CVE-2008-3656", "CVE-2008-3657", "CVE-2008-3790", "CVE-2008-3905");
script_summary(english: "Check for the version of the ruby package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"ruby-1.8.6-5.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.6-5.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.6-5.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.6-5.3mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.6-9p114.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.6-9p114.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.6-9p114.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.6-9p114.2mdv2008.1", release:"MDK2008.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ruby-", release:"MDK2008.0")
 || rpm_exists(rpm:"ruby-", release:"MDK2008.1") )
{
 set_kb_item(name:"CVE-2008-3443", value:TRUE);
 set_kb_item(name:"CVE-2008-3655", value:TRUE);
 set_kb_item(name:"CVE-2008-3656", value:TRUE);
 set_kb_item(name:"CVE-2008-3657", value:TRUE);
 set_kb_item(name:"CVE-2008-3790", value:TRUE);
 set_kb_item(name:"CVE-2008-3905", value:TRUE);
}
exit(0, "Host is not affected");
