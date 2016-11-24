# This script was automatically generated from the dsa-836
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(19805);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "836");
 script_cve_id("CVE-2005-2960", "CVE-2005-3137");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-836 security update');
 script_set_attribute(attribute: 'description', value:
'Javier Fernández-Sanguino Peña discovered insecure temporary file use
in cfengine2, a tool for configuring and maintaining networked
machines, that can be exploited by a symlink attack to overwrite
arbitrary files owned by the user executing cfengine, which is
probably root.
The old stable distribution (woody) is not affected by this problem.
For the stable distribution (sarge) these problems have been fixed in
version 2.1.14-1sarge1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-836');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cfengine2 package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA836] DSA-836-1 cfengine2");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-836-1 cfengine2");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cfengine2', release: '3.1', reference: '2.1.14-1sarge1');
deb_check(prefix: 'cfengine2-doc', release: '3.1', reference: '2.1.14-1sarge1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
