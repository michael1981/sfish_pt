# This script was automatically generated from the dsa-488
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15325);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "488");
 script_cve_id("CVE-2004-0404");
 script_bugtraq_id(10162);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-488 security update');
 script_set_attribute(attribute: 'description', value:
'Christian Jaeger reported a bug in logcheck which could potentially be
exploited by a local user to overwrite files with root privileges.
logcheck utilized a temporary directory under /var/tmp without taking
security precautions.  While this directory is created when logcheck
is installed, and while it exists there is no vulnerability, if at
any time this directory is removed, the potential for exploitation exists.
For the current stable distribution (woody) this problem has been
fixed in version 1.1.1-13.1woody1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2004/dsa-488');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2004/dsa-488
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA488] DSA-488-1 logcheck");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-488-1 logcheck");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'logcheck', release: '3.0', reference: '1.1.1-13.1woody1');
deb_check(prefix: 'logcheck-database', release: '3.0', reference: '1.1.1-13.1woody1');
deb_check(prefix: 'logtail', release: '3.0', reference: '1.1.1-13.1woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
