
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandriva Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(37401);
 script_version ("$Revision: 1.1 $");
 script_name(english: "MDVSA-2008:141: ruby");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDVSA-2008:141 (ruby).");
 script_set_attribute(attribute: "description", value: "Multiple vulnerabilities have been found in the Ruby interpreter and
in Webrick, the webserver bundled with Ruby.
Directory traversal vulnerability in WEBrick in Ruby 1.8 before
1.8.5-p115 and 1.8.6-p114, and 1.9 through 1.9.0-1, when running on
systems that support backslash () path separators or case-insensitive
file names, allows remote attackers to access arbitrary files via
(1) ..%5c (encoded backslash) sequences or (2) filenames that match
patterns in the :NondisclosureName option. (CVE-2008-1145)
Directory traversal vulnerability in WEBrick in Ruby 1.9.0
and earlier, when using NTFS or FAT filesystems, allows remote
attackers to read arbitrary CGI files via a trailing (1) + (plus),
(2) %2b (encoded plus), (3) . (dot), (4) %2e (encoded dot), or
(5) %20 (encoded space) character in the URI, possibly related to
the WEBrick::HTTPServlet::FileHandler and WEBrick::HTTPServer.new
functionality and the :DocumentRoot option. (CVE-2008-1891)
Multiple integer overflows in the rb_str_buf_append function in
Ruby 1.8.4 and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before
1.8.6-p230, 1.8.7 before 1.8.7-p22, and 1.9.0 before 1.9.0-2
allow context-dependent attackers to execute arbitrary code or
cause a denial of service via unknown vectors that trigger memory
corruption. (CVE-2008-2662)
Multiple integer overflows in the rb_ary_store function in Ruby
1.8.4 and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230,
and 1.8.7 before 1.8.7-p22 allow context-dependent attackers to
execute arbitrary code or cause a denial of service via unknown
vectors. (CVE-2008-2663)
The rb_str_format function in Ruby 1.8.4 and earlier, 1.8.5 before
1.8.5-p231, 1.8.6 before 1.8.6-p230, 1.8.7 before 1.8.7-p22, and 1.9.0
before 1.9.0-2 allows context-dependent attackers to trigger memory
corruption via unspecified vectors related to alloca. (CVE-2008-2664)
Integer overflow in the rb_ary_splice function in Ruby 1.8.4
and earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230,
and 1.8.7 before 1.8.7-p22 allows context-dependent attackers to
trigger memory corruption via unspecified vectors, aka the REALLOC_N
variant. (CVE-2008-2725)
Integer overflow in the rb_ary_splice function in Ruby 1.8.4 and
earlier, 1.8.5 before 1.8.5-p231, 1.8.6 before 1.8.6-p230, 1.8.7 before
1.8.7-p22, and 1.9.0 before 1.9.0-2 allows context-dependent attackers
to trigger memory corruption, aka the beg + rlen issue. (CVE-2008-2726)
Integer overflow in the rb_ary_fill function in array.c in Ruby before
revision 17756 allows context-dependent attackers to cause a denial
of service (crash) or possibly have unspecified other impact via a
call to the Array#fill method with a start (aka beg) argument greater
than ARY_MAX_SIZE. (CVE-2008-2376)
The updated packages have been patched to fix these issues.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDVSA-2008:141");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2008-1145", "CVE-2008-1891", "CVE-2008-2376", "CVE-2008-2662", "CVE-2008-2663", "CVE-2008-2664", "CVE-2008-2725", "CVE-2008-2726");
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

if ( rpm_check( reference:"ruby-1.8.5-5.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.5-5.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.5-5.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.5-5.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-1.8.6-5.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.8.6-5.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-doc-1.8.6-5.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"ruby-tk-1.8.6-5.2mdv2008.0", release:"MDK2008.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"ruby-", release:"MDK2007.1")
 || rpm_exists(rpm:"ruby-", release:"MDK2008.0") )
{
 set_kb_item(name:"CVE-2008-1145", value:TRUE);
 set_kb_item(name:"CVE-2008-1891", value:TRUE);
 set_kb_item(name:"CVE-2008-2376", value:TRUE);
 set_kb_item(name:"CVE-2008-2662", value:TRUE);
 set_kb_item(name:"CVE-2008-2663", value:TRUE);
 set_kb_item(name:"CVE-2008-2664", value:TRUE);
 set_kb_item(name:"CVE-2008-2725", value:TRUE);
 set_kb_item(name:"CVE-2008-2726", value:TRUE);
}
exit(0, "Host is not affected");
