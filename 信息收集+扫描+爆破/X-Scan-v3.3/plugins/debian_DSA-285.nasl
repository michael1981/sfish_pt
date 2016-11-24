# This script was automatically generated from the dsa-285
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15122);
 script_version("$Revision: 1.11 $");
 script_xref(name: "DSA", value: "285");
 script_cve_id("CVE-2003-0136");
 script_bugtraq_id(7334);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-285 security update');
 script_set_attribute(attribute: 'description', value:
'Karol Lewandowski discovered that psbanner, a printer filter that
creates a PostScript format banner and is part of LPRng, insecurely
creates a temporary file for debugging purpose when it is configured
as filter.  The program does not check whether this file already
exists or is linked to another place, psbanner writes its current environment
and called arguments to the file unconditionally with the user id
daemon.
For the stable distribution (woody) this problem has been fixed in
version 3.8.10-1.2.
The old stable distribution (potato) is not affected by this problem.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-285');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your lprng package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA285] DSA-285-1 lprng");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-285-1 lprng");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'lprng', release: '3.0', reference: '3.8.10-1.2');
deb_check(prefix: 'lprng-doc', release: '3.0', reference: '3.8.10-1.2');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
