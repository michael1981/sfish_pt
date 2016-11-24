# This script was automatically generated from the dsa-1722
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(35663);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1722");
 script_cve_id("CVE-2009-0361");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1722 security update');
 script_set_attribute(attribute: 'description', value:
'Derek Chan discovered that the PAM module for the Heimdal Kerberos
implementation allows reinitialisation of user credentials when run
from a setuid context, resulting in potential local denial of service
by overwriting the credential cache file or to local privilege
escalation.
For the stable distribution (etch), this problem has been fixed in
version 2.5-1etch1.
For the upcoming stable distribution (lenny), this problem has been
fixed in version 3.10-2.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1722');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpam-heimdal package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1722] DSA-1722-1 libpam-heimdal");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1722-1 libpam-heimdal");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-heimdal', release: '4.0', reference: '2.5-1etch1');
deb_check(prefix: 'libpam-heimdal', release: '5.0', reference: '3.10-2.1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
