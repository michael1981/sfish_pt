# This script was automatically generated from the dsa-233
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15070);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "233");
 script_cve_id("CVE-2003-0015");
 script_xref(name: "CERT", value: "650937");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-233 security update');
 script_set_attribute(attribute: 'description', value:
'Stefan Esser discovered a problem in cvs, a concurrent versions
system, which is used for many Free Software projects.  The current
version contains a flaw that can be used by a remote attacker to
execute arbitrary code on the CVS server under the user id the CVS
server runs as.  Anonymous read-only access is sufficient to exploit
this problem.
For the stable distribution (woody) this problem has been
fixed in version 1.11.1p1debian-8.1.
For the old stable distribution (potato) this problem has been fixed
in version 1.10.7-9.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-233');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cvs package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA233] DSA-233-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-233-1 cvs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cvs', release: '2.2', reference: '1.10.7-9.2');
deb_check(prefix: 'cvs-doc', release: '2.2', reference: '1.10.7-9.2');
deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-8.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
