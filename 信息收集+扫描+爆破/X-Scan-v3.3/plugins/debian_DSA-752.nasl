# This script was automatically generated from the dsa-752
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(18673);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "752");
 script_cve_id("CVE-2005-0988", "CVE-2005-1228");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-752 security update');
 script_set_attribute(attribute: 'description', value:
'Two problems have been discovered in gzip, the GNU compression
utility.  The Common Vulnerabilities and Exposures project identifies
the following problems.
    Imran Ghory discovered a race condition in the permissions setting
    code in gzip.  When decompressing a file in a directory an
    attacker has access to, gunzip could be tricked to set the file
    permissions to a different file the user has permissions to.
    Ulf Härnhammar discovered a path traversal vulnerability in
    gunzip.  When gunzip is used with the -N option an attacker could
    use
    this vulnerability to create files in an arbitrary directory with
    the permissions of the user.
For the oldstable distribution (woody) these problems have been fixed in
version 1.3.2-3woody5.
For the stable distribution (sarge) these problems have been fixed in
version 1.3.5-10.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-752');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gzip package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA752] DSA-752-1 gzip");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-752-1 gzip");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gzip', release: '3.0', reference: '1.3.2-3woody5');
deb_check(prefix: 'gzip', release: '3.1', reference: '1.3.5-10');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
