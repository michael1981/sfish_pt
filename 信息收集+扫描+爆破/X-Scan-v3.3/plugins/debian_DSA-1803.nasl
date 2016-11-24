# This script was automatically generated from the dsa-1803
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(38869);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1803");
 script_cve_id("CVE-2009-1755");
 script_xref(name: "CERT", value: "710316");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1803 security update');
 script_set_attribute(attribute: 'description', value:
'Ilja van Sprundel discovered that a buffer overflow in NSD, an authoritative
name service daemon, allowed to crash the server by sending a crafted packet,
creating a denial of service.
For the old stable distribution (etch), this problem has been fixed in
version 2.3.6-1+etch1 of the nsd package.
For the stable distribution (lenny), this problem has been fixed in
version 2.3.7-1.1+lenny1 of the nsd package and version 3.0.7-3.lenny2
of the nsd3 package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1803');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your nsd or nsd3 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1803] DSA-1803-1 nsd, nsd3");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1803-1 nsd, nsd3");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'nsd', release: '4.0', reference: '2.3.6-1+etch1');
deb_check(prefix: 'nsd', release: '5.0', reference: '2.3.7-1.1+lenny1');
deb_check(prefix: 'nsd3', release: '5.0', reference: '3.0.7-3.lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
