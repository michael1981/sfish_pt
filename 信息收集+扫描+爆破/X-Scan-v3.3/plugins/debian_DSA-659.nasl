# This script was automatically generated from the dsa-659
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16252);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "659");
 script_cve_id("CVE-2004-1340", "CVE-2005-0108");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-659 security update');
 script_set_attribute(attribute: 'description', value:
'Two problems have been discovered in the libpam-radius-auth package,
the PAM RADIUS authentication module.  The Common Vulnerabilities and
Exposures Project identifies the following problems:
    The Debian package accidentally installed its configuration file
    /etc/pam_radius_auth.conf world-readable.  Since it may possibly
    contain secrets all local users are able to read them if the
    administrator hasn\'t adjusted file permissions.  This problem is
    Debian specific.
    Leon Juranic discovered an integer underflow in the mod_auth_radius
    module for Apache which is also present in libpam-radius-auth.
For the stable distribution (woody) these problems have been fixed in
version 1.3.14-1.3.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-659');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your libpam-radius-auth package.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA659] DSA-659-1 libpam-radius-auth");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-659-1 libpam-radius-auth");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libpam-radius-auth', release: '3.0', reference: '1.3.14-1.3');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
