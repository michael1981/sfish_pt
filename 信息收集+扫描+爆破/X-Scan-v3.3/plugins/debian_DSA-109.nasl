# This script was automatically generated from the dsa-109
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14946);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "109");
 script_cve_id("CVE-2002-0230");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-109 security update');
 script_set_attribute(attribute: 'description', value:
'Due to unescaped HTML code Faq-O-Matic returned unverified scripting
code to the browser.  With some tweaking this enables an attacker to
steal cookies from one of the Faq-O-Matic moderators or the admin.
Cross-Site Scripting is a type of problem that allows a malicious
person to make another person run some JavaScript in their browser.
The JavaScript is executed on the victims machine and is in the
context of the website running the Faq-O-Matic Frequently Asked
Question manager.
This problem has been fixed in version 2.603-1.2 for the stable Debian
distribution and version 2.712-2 for the current testing/unstable
distribution.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-109');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your faqomatic package if you have it
installed.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA109] DSA-109-1 faqomatic");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-109-1 faqomatic");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'faqomatic', release: '2.2', reference: '2.603-1.2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
