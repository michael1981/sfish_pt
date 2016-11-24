# This script was automatically generated from the dsa-960
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(22826);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "960");
 script_cve_id("CVE-2005-4536");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-960 security update');
 script_set_attribute(attribute: 'description', value:
'The former update caused temporary files to be created in the current
working directory due to a wrong function argument.  This update will
create temporary files in the users home directory if HOME is set or
in the common temporary directory otherwise, usually /tmp.  For
completeness below is a copy of the original advisory text:
Niko Tyni discovered that the Mail::Audit module, a Perl library for
creating simple mail filters, logs to a temporary file with a
predictable filename in an insecure fashion when logging is turned on,
which is not the case by default.
For the old stable distribution (woody) these problems have been fixed in
version 2.0-4woody3.
For the stable distribution (sarge) these problems have been fixed in
version 2.1-5sarge4.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2006/dsa-960');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libmail-audit-perl package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA960] DSA-960-3 libmail-audit-perl");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-960-3 libmail-audit-perl");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libmail-audit-perl', release: '3.0', reference: '2.0-4woody3');
deb_check(prefix: 'mail-audit-tools', release: '3.0', reference: '2.0-4woody3');
deb_check(prefix: 'libmail-audit-perl', release: '3.1', reference: '2.1-5sarge4');
deb_check(prefix: 'mail-audit-tools', release: '3.1', reference: '2.1-5sarge4');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
