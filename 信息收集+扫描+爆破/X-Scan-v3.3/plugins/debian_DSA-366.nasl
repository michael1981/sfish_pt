# This script was automatically generated from the dsa-366
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15203);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "366");
 script_cve_id("CVE-2003-0656");
 script_bugtraq_id(8350);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-366 security update');
 script_set_attribute(attribute: 'description', value:
'eroaster, a frontend for burning CD-R media using cdrecord, does not
take appropriate security precautions when creating a temporary file
for use as a lockfile.  This bug could potentially be exploited to
overwrite arbitrary files with the privileges of the user running
eroaster.
For the stable distribution (woody) this problem has been fixed in
version 2.1.0.0.3-2woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-366');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-366
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA366] DSA-366-1 eroaster");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-366-1 eroaster");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'eroaster', release: '3.0', reference: '2.1.0.0.3-2woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
