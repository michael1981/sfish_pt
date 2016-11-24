# This script was automatically generated from the dsa-377
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15214);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "377");
 script_cve_id("CVE-1999-0997");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-377 security update');
 script_set_attribute(attribute: 'description', value:
'wu-ftpd, an FTP server, implements a feature whereby multiple files
can be fetched in the form of a dynamically constructed archive file,
such as a tar archive.  The names of the files to be included are
passed as command line arguments to tar, without protection against
them being interpreted as command-line options.  GNU tar supports
several command line options which can be abused, by means of this
vulnerability, to execute arbitrary programs with the privileges of
the wu-ftpd process.
Georgi Guninski pointed out that this vulnerability exists in Debian
woody.
For the stable distribution (woody) this problem has been fixed in
version 2.6.2-3woody2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-377');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-377
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA377] DSA-377-1 wu-ftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-377-1 wu-ftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'wu-ftpd', release: '3.0', reference: '2.6.2-3woody2');
deb_check(prefix: 'wu-ftpd-academ', release: '3.0', reference: '2.6.2-3woody2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
