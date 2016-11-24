# This script was automatically generated from the dsa-189
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15026);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "189");
 script_cve_id("CVE-2002-1245");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-189 security update');
 script_set_attribute(attribute: 'description', value:
'iDEFENSE reported about a vulnerability in LuxMan, a maze game for
GNU/Linux, similar to the PacMan arcade game.  When successfully
exploited a local attacker gains read-write access to the memory,
leading to a local root compromise in many ways, examples of which
include scanning the file for fragments of the master password file
and modifying kernel memory to re-map system calls.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2002/dsa-189');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your luxman package immediately.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA189] DSA-189-1 luxman");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-189-1 luxman");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'luxman', release: '3.0', reference: '0.41-17.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
