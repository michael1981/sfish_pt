# This script was automatically generated from the dsa-1770
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36146);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1770");
 script_cve_id("CVE-2008-4182", "CVE-2009-0930");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1770 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been found in imp4, a webmail component for
the horde framework. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2008-4182
It was discovered that imp4 suffers from a cross-site scripting (XSS)
attack via the user field in an IMAP session, which allows attackers to
inject arbitrary HTML code.
CVE-2009-0930
It was discovered that imp4 is prone to several cross-site scripting
(XSS) attacks via several vectors in the mail code allowing attackers
to inject arbitrary HTML code.
For the oldstable distribution (etch), these problems have been fixed in
version 4.1.3-4etch1.
For the stable distribution (lenny), these problems have been fixed in
version 4.2-4, which was already included in the lenny release.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1770');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your imp4 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1770] DSA-1770-1 imp4");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1770-1 imp4");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'imp4', release: '4.0', reference: '4.1.3-4etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
