# This script was automatically generated from the dsa-038
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14875);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "038");
 script_cve_id("CVE-2001-0416");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-038 security update');
 script_set_attribute(attribute: 'description', value:
'Former versions of sgml-tools created temporary files
directly in /tmp in an insecure fashion.  Version 1.0.9-15 and higher create a
subdirectory first and open temporary files within that directory. This has
been fixed in sgml-tools 1.0.9-15
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-038');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-038
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA038] DSA-038-1 sgml-tools");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-038-1 sgml-tools");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'sgml-tools', release: '2.2', reference: '1.0.9-15');
if (deb_report_get()) security_note(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
