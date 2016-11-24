# This script was automatically generated from the dsa-1387
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(27066);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1387");
 script_cve_id("CVE-2007-4743");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1387 security update');
 script_set_attribute(attribute: 'description', value:
'It has been discovered that the original patch for a buffer overflow in
svc_auth_gss.c in the RPCSEC_GSS RPC library in MIT Kerberos 5
(CVE-2007-3999,
DSA-1368-1) was insufficient to protect from arbitrary
code execution in some environments.
The old stable distribution (sarge) does not contain a librpcsecgss
package.
For the stable distribution (etch), this problem has been fixed in
version 0.14-2etch3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1387');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your librpcsecgss package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1387] DSA-1387-1 librpcsecgss");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1387-1 librpcsecgss");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'librpcsecgss-dev', release: '4.0', reference: '0.14-2etch3');
deb_check(prefix: 'librpcsecgss3', release: '4.0', reference: '0.14-2etch3');
deb_check(prefix: 'librpcsecgss', release: '4.0', reference: '0.14-2etch3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
