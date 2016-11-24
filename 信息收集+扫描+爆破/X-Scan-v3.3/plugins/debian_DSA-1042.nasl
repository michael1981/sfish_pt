# This script was automatically generated from the dsa-1042
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22584);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1042");
 script_cve_id("CVE-2006-1721");
 script_bugtraq_id(17446);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1042 security update');
 script_set_attribute(attribute: 'description', value:
'The Mu Security research team discovered a denial of service condition
in the Simple Authentication and Security Layer authentication library
(SASL) during DIGEST-MD5 negotiation.  This potentially affects
multiple products that use SASL DIGEST-MD5 authentication including
OpenLDAP, Sendmail, Postfix, etc.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) this problem has been fixed in
version 2.1.19-1.5sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1042');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cyrus-sasl2 packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1042] DSA-1042-1 cyrus-sasl2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1042-1 cyrus-sasl2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libsasl2', release: '3.1', reference: '2.1.19-1.5sarge1');
deb_check(prefix: 'libsasl2-dev', release: '3.1', reference: '2.1.19-1.5sarge1');
deb_check(prefix: 'libsasl2-modules', release: '3.1', reference: '2.1.19-1.5sarge1');
deb_check(prefix: 'libsasl2-modules-gssapi-heimdal', release: '3.1', reference: '2.1.19-1.5sarge1');
deb_check(prefix: 'libsasl2-modules-kerberos-heimdal', release: '3.1', reference: '2.1.19-1.5sarge1');
deb_check(prefix: 'libsasl2-modules-sql', release: '3.1', reference: '2.1.19-1.5sarge1');
deb_check(prefix: 'sasl2-bin', release: '3.1', reference: '2.1.19-1.5sarge1');
deb_check(prefix: 'cyrus-sasl2', release: '3.1', reference: '2.1.19-1.5sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
