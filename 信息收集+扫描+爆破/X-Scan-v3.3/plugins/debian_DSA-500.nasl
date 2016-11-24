# This script was automatically generated from the dsa-500
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15337);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "500");
 script_cve_id("CVE-2004-0422");
 script_bugtraq_id(10259);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-500 security update');
 script_set_attribute(attribute: 'description', value:
'Tatsuya Kinoshita discovered a vulnerability in flim, an emacs library
for working with internet messages, where temporary files were created
without taking appropriate precautions.  This vulnerability could
potentially be exploited by a local user to overwrite files with the
privileges of the user running emacs.
For the current stable distribution (woody) this problem has been
fixed in version 1.14.3-9woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-500');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-500
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA500] DSA-500-1 flim");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-500-1 flim");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'flim', release: '3.0', reference: '1.14.3-9woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
