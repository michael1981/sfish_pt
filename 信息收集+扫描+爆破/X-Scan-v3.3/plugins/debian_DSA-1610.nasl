# This script was automatically generated from the dsa-1610
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33508);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1610");
 script_cve_id("CVE-2008-2927");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1610 security update');
 script_set_attribute(attribute: 'description', value:
'It was discovered that gaim, an multi-protocol instant messaging client,
was vulnerable to several integer overflows in its MSN protocol handlers.
These could allow a remote attacker to execute arbitrary code.
For the stable distribution (etch), this problem has been fixed in version
1:2.0.0+beta5-10etch1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1610');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gaim package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1610] DSA-1610-1 gaim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1610-1 gaim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gaim', release: '4.0', reference: '2.0.0+beta5-10etch1');
deb_check(prefix: 'gaim-data', release: '4.0', reference: '2.0.0+beta5-10etch1');
deb_check(prefix: 'gaim-dbg', release: '4.0', reference: '2.0.0+beta5-10etch1');
deb_check(prefix: 'gaim-dev', release: '4.0', reference: '2.0.0+beta5-10etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
