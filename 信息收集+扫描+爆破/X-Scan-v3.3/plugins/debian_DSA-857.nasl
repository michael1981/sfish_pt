# This script was automatically generated from the dsa-857
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19965);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "857");
 script_cve_id("CVE-2005-4803");
 script_bugtraq_id(15050);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-857 security update');
 script_set_attribute(attribute: 'description', value:
'Javier Fernández-Sanguino Peña discovered insecure temporary file
creation in graphviz, a rich set of graph drawing tools, that can be
exploited to overwrite arbitrary files by a local attacker.
For the old stable distribution (woody) this problem probably persists
but the package is non-free.
For the stable distribution (sarge) this problem has been fixed in
version 2.2.1-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-857');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your graphviz package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA857] DSA-857-1 graphviz");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-857-1 graphviz");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'graphviz', release: '3.1', reference: '2.2.1-1sarge1');
deb_check(prefix: 'graphviz-dev', release: '3.1', reference: '2.2.1-1sarge1');
deb_check(prefix: 'graphviz-doc', release: '3.1', reference: '2.2.1-1sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
