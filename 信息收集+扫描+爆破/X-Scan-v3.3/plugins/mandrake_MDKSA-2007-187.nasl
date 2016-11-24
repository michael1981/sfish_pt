
#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory ADVISORY
#

include("compat.inc");

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(26107);
 script_version ("$Revision: 1.3 $");
 script_name(english: "MDKSA-2007:187: php");
 script_set_attribute(attribute: "synopsis", value: 
"The remote host is missing the patch for the advisory MDKSA-2007:187 (php).");
 script_set_attribute(attribute: "description", value: "Numerous vulnerabilities were discovered in the PHP scripting language
that are corrected with this update.
An integer overflow in the substr_compare() function allows
context-dependent attackers to read sensitive memory via a large
value in the length argument. This only affects PHP5 (CVE-2007-1375).
A stack-based buffer overflow in the zip:// URI wrapper in PECL
ZIP 1.8.3 and earlier allowes remote attackers to execute arbitrary
code via a long zip:// URL. This only affects Corporate Server 4.0
(CVE-2007-1399).
A CRLF injection vulnerability in the FILTER_VALIDATE_EMAIL filter
could allow an attacker to inject arbitrary email headers via a
special email address. This only affects Mandriva Linux 2007.1
(CVE-2007-1900).
The mcrypt_create_iv() function calls php_rand_r() with an
uninitialized seed variable, thus always generating the same
initialization vector, which may allow an attacker to decrypt
certain data more easily because of the guessable encryption keys
(CVE-2007-2727).
The soap extension calls php_rand_r() with an uninitialized seec
variable, which has unknown impact and attack vectors; an issue
similar to that affecting mcrypt_create_iv(). This only affects PHP5
(CVE-2007-2728).
The substr_count() function allows attackers to obtain sensitive
information via unspecified vectors. This only affects PHP5
(CVE-2007-2748).
An infinite loop was found in the gd extension that could be used to
cause a denial of service if a script were forced to process certain
PNG images from untrusted sources (CVE-2007-2756).
An integer overflow flaw was found in the chunk_split() function that
ould possibly execute arbitrary code as the apache user if a remote
attacker was able to pass arbitrary data to the third argument of
chunk_split() (CVE-2007-2872).
A flaw in the PHP session cookie handling could allow an attacker to
create a cross-site cookie insertion attack if a victim followed an
untrusted carefully-crafted URL (CVE-2007-3799).
Various integer overflow flaws were discovered in the PHP gd extension
that could allow a remote attacker to execute arbitrary code as the
apache user (CVE-2007-3996).
A flaw in the wordwrap() frunction could result in a denial of ervice
if a remote attacker was able to pass arbitrary data to the function
(CVE-2007-3998).
A flaw in the money_format() function could result in an information
leak or denial of service if a remote attacker was able to pass
arbitrary data to this function; this situation would be unlikely
however (CVE-2007-4658).
A bug in the PHP session cookie handling could allow an attacker to
stop a victim from viewing a vulnerable website if the victim first
visited a malicious website under the control of the attacker who
was able to use that page to set a cookie for the vulnerable website
(CVE-2007-4670).
Updated packages have been patched to prevent these issues.
In addition, PECL ZIP version 1.8.10 is being provided for Corporate
Server 4.0.
");
 script_set_attribute(attribute: "cvss_vector", value: "CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
script_set_attribute(attribute: "see_also", value: "http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2007:187");
script_set_attribute(attribute: "solution", value: "Apply the newest security patches from Mandriva.");
script_end_attributes();

script_cve_id("CVE-2007-1375", "CVE-2007-1399", "CVE-2007-1900", "CVE-2007-2727", "CVE-2007-2728", "CVE-2007-2748", "CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4670");
script_summary(english: "Check for the version of the php package");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009 Tenable Network Security");
 script_family(english: "Mandriva Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");

if ( ! get_kb_item("Host/Mandrake/rpm-list") ) exit(1, "Could not get the list of packages");

if ( rpm_check( reference:"libphp5_common5-5.1.6-1.9mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.1.6-1.9mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.1.6-1.9mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.1.6-1.9mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.1.6-1.9mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.1.6-1.3mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mcrypt-5.1.6-1.1mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-soap-5.1.6-1.2mdv2007.0", release:"MDK2007.0", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"libphp5_common5-5.2.1-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cgi-5.2.1-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-cli-5.2.1-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-devel-5.2.1-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-fcgi-5.2.1-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-gd-5.2.1-1.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-mcrypt-5.2.1-1.1mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-openssl-5.2.1-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-soap-5.2.1-1.2mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if ( rpm_check( reference:"php-zlib-5.2.1-4.3mdv2007.1", release:"MDK2007.1", yank:"mdv") )
{
 security_hole(port:0, extra:rpm_report_get());
 exit(0);
}
if (rpm_exists(rpm:"php-", release:"MDK2007.0")
 || rpm_exists(rpm:"php-", release:"MDK2007.1") )
{
 set_kb_item(name:"CVE-2007-1375", value:TRUE);
 set_kb_item(name:"CVE-2007-1399", value:TRUE);
 set_kb_item(name:"CVE-2007-1900", value:TRUE);
 set_kb_item(name:"CVE-2007-2727", value:TRUE);
 set_kb_item(name:"CVE-2007-2728", value:TRUE);
 set_kb_item(name:"CVE-2007-2748", value:TRUE);
 set_kb_item(name:"CVE-2007-2756", value:TRUE);
 set_kb_item(name:"CVE-2007-2872", value:TRUE);
 set_kb_item(name:"CVE-2007-3799", value:TRUE);
 set_kb_item(name:"CVE-2007-3996", value:TRUE);
 set_kb_item(name:"CVE-2007-3998", value:TRUE);
 set_kb_item(name:"CVE-2007-4658", value:TRUE);
 set_kb_item(name:"CVE-2007-4670", value:TRUE);
}
exit(0, "Host is not affected");
