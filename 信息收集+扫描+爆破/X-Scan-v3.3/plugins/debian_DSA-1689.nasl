# This script was automatically generated from the dsa-1689
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35252);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1689");
 script_cve_id("CVE-2008-4242");
 script_bugtraq_id(31289);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1689 security update');
 script_set_attribute(attribute: 'description', value:
'Maksymilian Arciemowicz of securityreason.com reported that ProFTPD is
vulnerable to cross-site request forgery (CSRF) attacks and executes
arbitrary FTP commands via a long ftp:// URI that leverages an
existing session from the FTP client implementation in a web browser.
For the stable distribution (etch) this problem has been fixed in
version 1.3.0-19etch2 and in version 1.3.1-15~bpo40+1 for backports.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1689');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your proftpd-dfsg package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1689] DSA-1689-1 proftpd-dfsg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1689-1 proftpd-dfsg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '4.0', reference: '1.3.0-19etch2');
deb_check(prefix: 'proftpd-doc', release: '4.0', reference: '1.3.0-19etch2');
deb_check(prefix: 'proftpd-ldap', release: '4.0', reference: '1.3.0-19etch2');
deb_check(prefix: 'proftpd-mysql', release: '4.0', reference: '1.3.0-19etch2');
deb_check(prefix: 'proftpd-pgsql', release: '4.0', reference: '1.3.0-19etch2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
