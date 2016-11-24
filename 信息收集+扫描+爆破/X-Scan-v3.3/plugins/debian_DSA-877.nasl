# This script was automatically generated from the dsa-877
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22743);
 script_version("$Revision: 1.7 $");
 script_xref(name: "DSA", value: "877");
 script_cve_id("CVE-2005-3123", "CVE-2005-3424", "CVE-2005-3425");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-877 security update');
 script_set_attribute(attribute: 'description', value:
'Steve Kemp discovered two vulnerabilities in gnump3d, a streaming
server for MP3 and OGG files.  The Common Vulnerabilities and
Exposures Project identifies the following problems:
CVE-2005-3122
    The 404 error page does not strip malicious javascript content
    from the resulting page, which would be executed in the victims
    browser.
CVE-2005-3123
    By using specially crafting URLs it is possible to read arbitrary
    files to which the user of the streaming server has access to.
The old stable distribution (woody) does not contain a gnump3d package.
For the stable distribution (sarge) these problems have been fixed in
version 2.9.3-1sarge2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-877');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gnump3d package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA877] DSA-877-1 gnump3d");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-877-1 gnump3d");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnump3d', release: '3.1', reference: '2.9.3-1sarge2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
