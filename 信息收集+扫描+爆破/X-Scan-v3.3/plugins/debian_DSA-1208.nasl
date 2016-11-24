# This script was automatically generated from the dsa-1208
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(23657);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "1208");
 script_cve_id("CVE-2005-4534", "CVE-2006-5453");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1208 security update');
 script_set_attribute(attribute: 'description', value:
'Several remote vulnerabilities have been discovered in the Bugzilla
bug tracking system, which may lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the following
problems:
CVE-2005-4534
    Javier Fernández-Sanguino Peña discovered that insecure temporary
    file usage may lead to denial of service through a symlink attack.
CVE-2006-5453
    Several cross-site scripting vulnerabilities may lead to injection
    of arbitrary web script code.
For the stable distribution (sarge) these problems have been fixed in
version 2.16.7-7sarge2.
For the upcoming stable distribution (etch) these problems have been
fixed in version 2.22.1-1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-1208');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bugzilla packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1208] DSA-1208-1 bugzilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1208-1 bugzilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bugzilla', release: '3.1', reference: '2.16.7-7sarge2');
deb_check(prefix: 'bugzilla-doc', release: '3.1', reference: '2.16.7-7sarge2');
deb_check(prefix: 'bugzilla', release: '4.0', reference: '2.22.1-1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
