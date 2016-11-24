# This script was automatically generated from the dsa-061
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14898);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "061");
 script_cve_id("CVE-2001-0522");
 script_bugtraq_id(2797);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-061 security update');
 script_set_attribute(attribute: 'description', value:
'The version of GnuPG (GNU Privacy Guard, an OpenPGP implementation)
as distributed in Debian GNU/Linux 2.2 suffers from two problems:


fish stiqz reported on bugtraq that there was a printf format
problem in the do_get() function: it printed a prompt which included
the filename that was being decrypted without checking for
possible printf format attacks. This could be exploited by tricking
someone into decrypting a file with a specially crafted filename.

The second bug is related to importing secret keys: when gnupg
imported a secret key it would immediately make the associated
public key fully trusted which changes your web of trust without
asking for a confirmation. To fix this you now need a special
option to import a secret key.


Both problems have been fixed in version 1.0.6-0potato1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-061');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-061
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA061] DSA-061-1 gnupg");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-061-1 gnupg");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'gnupg', release: '2.2', reference: '1.0.6-0potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
