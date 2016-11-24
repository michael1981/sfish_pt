# This script was automatically generated from the dsa-736
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18596);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "736");
 script_cve_id("CVE-2005-1266");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-736 security update');
 script_set_attribute(attribute: 'description', value:
'A vulnerability was recently found in the way that SpamAssassin parses
certain email headers. This vulnerability could cause SpamAssassin to
consume a large number of CPU cycles when processing messages containing
these headers, leading to a potential denial of service (DOS) attack. 
The version of SpamAssassin in the old stable distribution (woody) is
not vulnerable.
For the stable distribution (sarge), this problem has been fixed in
version 3.0.3-2. Note that packages are not yet ready for certain
architectures; these will be released as they become available.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-736');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your sarge or sid spamassassin package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA736] DSA-736-1 spamassassin");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-736-1 spamassassin");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'spamassassin', release: '3.1', reference: '3.0.3-2');
deb_check(prefix: 'spamc', release: '3.1', reference: '3.0.3-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
