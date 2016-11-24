# This script was automatically generated from the dsa-686
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(17136);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "686");
 script_cve_id("CVE-2005-0372");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-686 security update');
 script_set_attribute(attribute: 'description', value:
'Albert Puigsech Galicia discovered a directory traversal vulnerability
in a proprietary FTP client (CVE-2004-1376) which is also present in
gftp, a GTK+ FTP client.  A malicious server could provide a specially
crafted filename that could cause arbitrary files to be overwritten or
created by the client.
For the stable distribution (woody) this problem has been fixed in
version 2.0.11-1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-686');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gftp package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA686] DSA-686-1 gftp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-686-1 gftp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gftp', release: '3.0', reference: '2.0.11-1woody1');
deb_check(prefix: 'gftp-common', release: '3.0', reference: '2.0.11-1woody1');
deb_check(prefix: 'gftp-gtk', release: '3.0', reference: '2.0.11-1woody1');
deb_check(prefix: 'gftp-text', release: '3.0', reference: '2.0.11-1woody1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
