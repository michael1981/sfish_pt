# This script was automatically generated from the dsa-388
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15225);
 script_version("$Revision: 1.10 $");
 script_xref(name: "DSA", value: "388");
 script_cve_id("CVE-2003-0690", "CVE-2003-0692");
 script_bugtraq_id(8635, 8636);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-388 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities were discovered in kdebase:
  KDM in KDE 3.1.3 and earlier does not verify whether the pam_setcred
  function call succeeds, which may allow attackers to gain root
  privileges by triggering error conditions within PAM modules, as
  demonstrated in certain configurations of the MIT pam_krb5 module.
  KDM in KDE 3.1.3 and earlier uses a weak session cookie generation
  algorithm that does not provide 128 bits of entropy, which allows
  attackers to guess session cookies via brute force methods and gain
  access to the user session.
These vulnerabilities are described in the following security
advisory from KDE:
http://www.kde.org/info/security/advisory-20030916-1.txt
For the current stable distribution (woody) these problems have been
fixed in version 4:2.2.2-14.7.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-388');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2003/dsa-388
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA388] DSA-388-1 kdebase");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-388-1 kdebase");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'kate', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdebase', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdebase-audiolibs', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdebase-dev', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdebase-doc', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdebase-libs', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdewallpapers', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kdm', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'konqueror', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'konsole', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'kscreensaver', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'libkonq-dev', release: '3.0', reference: '2.2.2-14.7');
deb_check(prefix: 'libkonq3', release: '3.0', reference: '2.2.2-14.7');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
