# This script was automatically generated from the dsa-933
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22799);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "933");
 script_cve_id("CVE-2005-3539");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-933 security update');
 script_set_attribute(attribute: 'description', value:
'Patrice Fournier found that hylafax passes unsanitized user data in the
notify script, allowing users with the ability to submit jobs to run
arbitrary commands  with the privileges of the hylafax server.
For the old stable distribution (woody) this problem has been fixed in
version 4.1.1-4woody1.
For the stable distribution (sarge) this problem has been fixed in
version 4.2.1-5sarge3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-933');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hylafax package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA933] DSA-933-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-933-1 hylafax");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-4woody1');
deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-4woody1');
deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-4woody1');
deb_check(prefix: 'hylafax-client', release: '3.1', reference: '4.2.1-5sarge3');
deb_check(prefix: 'hylafax-doc', release: '3.1', reference: '4.2.1-5sarge3');
deb_check(prefix: 'hylafax-server', release: '3.1', reference: '4.2.1-5sarge3');
deb_check(prefix: 'hylafax', release: '3.1', reference: '4.2.1-5sarge3');
deb_check(prefix: 'hylafax', release: '3.0', reference: '4.1.1-4woody1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
