# This script was automatically generated from the dsa-674
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16348);
 script_version("$Revision: 1.13 $");
 script_xref(name: "DSA", value: "674");
 script_cve_id("CVE-2004-1177", "CVE-2005-0202");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-674 security update');
 script_set_attribute(attribute: 'description', value:
'Due to an incompatibility between Python 1.5 and 2.1 the last mailman
update did not run with Python 1.5 anymore.  This problem is corrected
with this update.  This advisory only updates the packages updated
with DSA 674-2.  The version in unstable is not affected since it is
not supposed to work with Python 1.5 anymore.  For completeness below
is the original advisory text:
Two security related problems have been discovered in mailman,
web-based GNU mailing list manager.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Florian Weimer discovered a cross-site scripting vulnerability in
    mailman\'s automatically generated error messages.  An attacker
    could craft a URL containing JavaScript (or other content
    embedded into HTML) which triggered a mailman error page that
    would include the malicious code verbatim.
    Several listmasters have noticed unauthorised access to archives
    of private lists and the list configuration itself, including the
    users passwords.  Administrators are advised to check the
    webserver logfiles for requests that contain "/...../" and the
    path to the archives or configuration.  This does only seem to
    affect installations running on web servers that do not strip
    slashes, such as Apache 1.3.
For the stable distribution (woody) these problems have been fixed in
version 2.0.11-1woody11.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-674');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your mailman package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA674] DSA-674-3 mailman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-674-3 mailman");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mailman', release: '3.0', reference: '2.0.11-1woody11');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
