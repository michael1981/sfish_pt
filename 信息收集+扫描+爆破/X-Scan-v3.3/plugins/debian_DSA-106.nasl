# This script was automatically generated from the dsa-106
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14943);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "106");
 script_cve_id("CVE-2002-0048");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-106 security update');
 script_set_attribute(attribute: 'description', value:
'Sebastian Krahmer found several places in rsync (a popular tool to synchronise files between machines)
where signed and unsigned numbers
were mixed which resulted in insecure code (see <a
href="http://online.securityfocus.com/bid/3958">securityfocus.com</a>).
This could be abused by
remote users to write 0-bytes in rsync\'s memory and trick rsync into
executing arbitrary code.

This has been fixed in version 2.3.2-1.3 and we recommend you upgrade
your rsync package immediately.
Unfortunately the patch used to fix that problem broke rsync.
This has been fixed in version 2.3.2-1.5 and we recommend you
upgrade to that version immediately.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-106');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2002/dsa-106
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA106] DSA-106-2 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-106-2 rsync");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rsync', release: '2.2', reference: '2.3.2-1.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
