# This script was automatically generated from the dsa-909
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22775);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "909");
 script_cve_id("CVE-2005-3759");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-909 security update');
 script_set_attribute(attribute: 'description', value:
'Daniel Schreckling discovered that the MIME viewer in horde3, a web
application suite, does not always sanitise its input leaving a
possibility to force the return of malicious code that could be
executed on the victims machine.
The old stable distribution (woody) does not contain horde3 packages.
For the stable distribution (sarge) these problems have been fixed in
version 3.0.4-4sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-909');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your horde3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA909] DSA-909-1 horde3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-909-1 horde3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde3', release: '3.1', reference: '3.0.4-4sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
