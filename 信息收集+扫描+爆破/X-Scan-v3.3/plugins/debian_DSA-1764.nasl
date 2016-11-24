# This script was automatically generated from the dsa-1764
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(36118);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "1764");
 script_cve_id("CVE-2009-1253", "CVE-2009-1254");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1764 security update');
 script_set_attribute(attribute: 'description', value:
'Several vulnerabilities have been discovered in Tunapie, a GUI frontend
to video and radio streams. The Common Vulnerabilities and Exposures
project identifies the following problems:
CVE-2009-1253
    Kees Cook discovered that insecure handling of temporary files may
    lead to local denial of service through symlink attacks.
CVE-2009-1254
    Mike Coleman discovered that insufficient escaping of stream
    URLs may lead to the execution of arbitrary commands if a user
    is tricked into opening a malformed stream URL.
For the old stable distribution (etch), these problems have been fixed
in version 1.3.1-1+etch2. Due to a technical problem, this update cannot
be released synchronously with the stable (lenny) version, but will
appear soon.
For the stable distribution (lenny), these problems have been fixed in
version 2.1.8-2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1764');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your tunapie package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1764] DSA-1764-1 tunapie");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1764-1 tunapie");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'tunapie', release: '5.0', reference: '2.1.8-2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
