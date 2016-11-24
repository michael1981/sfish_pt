# This script was automatically generated from the dsa-715
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18151);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "715");
 script_cve_id("CVE-2004-1342", "CVE-2004-1343");
 script_xref(name: "CERT", value: "327037");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-715 security update');
 script_set_attribute(attribute: 'description', value:
'Several problems have been discovered in the CVS server, which serves
the popular Concurrent Versions System.  The Common Vulnerabilities and
Exposures project identifies the following problems:
    Maks Polunin and Alberto Garcia discovered independently that
    using the pserver access method in connection with the repouid
    patch that Debian uses it is possible to bypass the password and
    gain access to the repository in question.
    Alberto Garcia discovered that a remote user can cause the cvs
    server to crash when the cvs-repouids file exists but does not
    contain a mapping for the current repository, which can be used as
    a denial of service attack.
For the stable distribution (woody) these problems have been fixed in
version 1.11.1p1debian-10.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-715');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your cvs package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA715] DSA-715-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-715-1 cvs");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'cvs', release: '3.0', reference: '1.11.1p1debian-10');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
