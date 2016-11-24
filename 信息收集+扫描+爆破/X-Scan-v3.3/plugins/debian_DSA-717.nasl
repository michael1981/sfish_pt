# This script was automatically generated from the dsa-717
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18153);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "717");
 script_cve_id("CVE-2003-0826", "CVE-2005-0814");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-717 security update');
 script_set_attribute(attribute: 'description', value:
'Several security relevant problems have been discovered in lsh, the
alternative secure shell v2 (SSH2) protocol server.  The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities:
    Bennett Todd discovered a heap buffer overflow in lshd which could
    lead to the execution of arbitrary code.
    Niels Möller discovered a denial of service condition in lshd.
For the stable distribution (woody) these problems have been fixed in
version 1.2.5-2woody3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-717');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lsh-server package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA717] DSA-717-1 lsh-utils");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-717-1 lsh-utils");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lsh-client', release: '3.0', reference: '1.2.5-2woody3');
deb_check(prefix: 'lsh-server', release: '3.0', reference: '1.2.5-2woody3');
deb_check(prefix: 'lsh-utils', release: '3.0', reference: '1.2.5-2woody3');
deb_check(prefix: 'lsh-utils-doc', release: '3.0', reference: '1.2.5-2woody3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
