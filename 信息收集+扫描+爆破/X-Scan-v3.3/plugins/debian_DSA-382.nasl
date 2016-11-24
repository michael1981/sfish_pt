# This script was automatically generated from the dsa-382
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15219);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "382");
 script_cve_id("CVE-2003-0682", "CVE-2003-0693", "CVE-2003-0695");
 script_xref(name: "CERT", value: "333628");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-382 security update');
 script_set_attribute(attribute: 'description', value:
'A bug has been found in OpenSSH\'s buffer handling where a buffer could
be marked as grown when the actual reallocation failed.
DSA-382-2:
This advisory is an addition to the earlier DSA-382-1 advisory: two more
buffer handling problems have been found in addition to the one
described in DSA-382-1. It is not known if these bugs are exploitable,
but as a precaution an upgrade is advised.
DSA-382-3:
This advisory is an addition to the earlier DSA-382-1 and DSA-382-2
advisories: Solar Designer found four more bugs in OpenSSH that may be
exploitable.
For the Debian stable distribution (woody) these bugs have been fixed 
in version
1:3.4p1-1.woody.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-382');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-382
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA382] DSA-382-3 ssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-382-3 ssh");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'ssh', release: '3.0', reference: '3.4p1-1.woody.3');
deb_check(prefix: 'ssh-askpass-gnome', release: '3.0', reference: '3.4p1-1.woody.3');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
