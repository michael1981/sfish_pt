# This script was automatically generated from the dsa-1792
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38702);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1792");
 script_cve_id("CVE-2009-1575", "CVE-2009-1576");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1792 security update');
 script_set_attribute(attribute: 'description', value:
'Multiple vulnerabilities have been discovered in drupal, a web content
management system.  The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-1575
    pod.Edge discovered a cross-site scripting vulnerability due that can be
    triggered when some browsers interpret UTF-8 strings as UTF-7 if they
    appear before the generated HTML document defines its Content-Type.
    This allows a malicious user to execute arbitrary javascript in the
    context of the web site if they\'re allowed to post content.
CVE-2009-1576
    Moritz Naumann discovered an information disclosure vulnerability. If
    a user is tricked into visiting the site via a specially crafted URL
    and then submits a form (such as the search box) from that page, the
    information in their form submission may be directed to a third-party
    site determined by the URL and thus disclosed to the third party. The
    third party site may then execute a cross-site request forgery attack
    against the submitted form.
The old stable distribution (etch) does not contain drupal and is not
affected.
For the stable distribution (lenny), these problems have been fixed in version
6.6-3lenny1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1792');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your drupal6 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1792] DSA-1792-1 drupal6");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1792-1 drupal6");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'drupal6', release: '5.0', reference: '6.6-3lenny1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
