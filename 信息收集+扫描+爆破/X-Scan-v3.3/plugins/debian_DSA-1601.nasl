# This script was automatically generated from the dsa-1601
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33402);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1601");
 script_cve_id("CVE-2007-1599", "CVE-2008-0664");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1601 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in Wordpress,
the weblog manager. The Common Vulnerabilities and Exposures project
identifies the following problems:
CVE-2007-1599
    WordPress allows remote attackers to redirect authenticated users
    to other websites and potentially obtain sensitive information.
CVE-2008-0664
    The XML-RPC implementation, when registration is enabled, allows
    remote attackers to edit posts of other blog users.
For the stable distribution (etch), these problems have been fixed in
version 2.0.10-1etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1601');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your wordpress package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1601] DSA-1601-1 wordpress");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1601-1 wordpress");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wordpress', release: '4.0', reference: '2.0.10-1etch3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
