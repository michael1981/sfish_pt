# This script was automatically generated from the dsa-325
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15162);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "325");
 script_cve_id("CVE-2003-0438");
 script_bugtraq_id(7987);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-325 security update');
 script_set_attribute(attribute: 'description', value:
'eldav, a WebDAV client for Emacs, creates temporary files without
taking appropriate security precautions.  This vulnerability could be
exploited by a local user to create or overwrite files with the
privileges of the user running emacs and eldav.
For the stable distribution (woody) this problem has been fixed in
version 0.0.20020411-1woody1.
The old stable distribution (potato) does not contain an eldav
package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-325');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-325
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA325] DSA-325-1 eldav");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-325-1 eldav");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'eldav', release: '3.0', reference: '0.0.20020411-1woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
