# This script was automatically generated from the dsa-1247
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(25225);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1247");
 script_cve_id("CVE-2006-5989");
 script_bugtraq_id(21214);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1247 security update');
 script_set_attribute(attribute: 'description', value:
'An off-by-one error leading to a heap-based buffer overflow has been
identified in libapache-mod-auth-kerb, an Apache module for Kerberos
authentication.  The error could allow an attacker to trigger an
application crash or potentially execute arbitrary code by sending a
specially crafted kerberos message.
For the stable distribution (sarge), this problem has been fixed in
version 4.996-5.0-rc6-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2007/dsa-1247');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libapache-mod-auth-kerb package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1247] DSA-1247-1 libapache-mod-auth-kerb");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1247-1 libapache-mod-auth-kerb");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libapache-mod-auth-kerb', release: '3.1', reference: '4.996-5.0-rc6-1sarge1');
deb_check(prefix: 'libapache2-mod-auth-kerb', release: '3.1', reference: '4.996-5.0-rc6-1sarge1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
