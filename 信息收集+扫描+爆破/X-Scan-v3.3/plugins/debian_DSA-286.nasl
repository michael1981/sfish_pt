# This script was automatically generated from the dsa-286
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15123);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "286");
 script_cve_id("CVE-2003-0207");
 script_bugtraq_id(7337);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-286 security update');
 script_set_attribute(attribute: 'description', value:
'Paul Szabo discovered insecure creation of a temporary file in
ps2epsi, a script that is distributed as part of gs-common which
contains common files for different Ghostscript releases.  ps2epsi uses
a temporary file in the process of invoking ghostscript.  This file
was created in an insecure fashion, which could allow a local attacker
to overwrite files owned by a user who invokes ps2epsi.
For the stable distribution (woody) this problem has been fixed in
version 0.3.3.0woody1.
The old stable distribution (potato) is not affected by this problem.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-286');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your gs-common package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA286] DSA-286-1 gs-common");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-286-1 gs-common");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gs-common', release: '3.0', reference: '0.3.3.0woody1');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
