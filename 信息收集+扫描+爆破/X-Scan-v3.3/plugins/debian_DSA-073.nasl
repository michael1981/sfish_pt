# This script was automatically generated from the dsa-073
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14910);
 script_version("$Revision: 1.9 $");
 script_xref(name: "DSA", value: "073");
 script_cve_id("CVE-2001-1257", "CVE-2001-1258", "CVE-2001-1370");
 script_bugtraq_id(3082, 3083);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-073 security update');
 script_set_attribute(attribute: 'description', value:
'The Horde team released version 2.2.6 of IMP (a web based IMAP mail
program) which fixes three security problems. Their release announcement
describes them as follows:


 A PHPLIB vulnerability allowed an attacker to provide a value for the
   array element $_PHPLIB[libdir], and thus to get scripts from another
   server to load and execute.  This vulnerability is remotely
   exploitable.  (Horde 1.2.x ships with its own customized version of
   PHPLIB, which has now been patched to prevent this problem.)

 By using tricky encodings of "javascript:" an attacker can cause
   malicious JavaScript code to execute in the browser of a user reading
   email sent by attacker.  (IMP 2.2.x already filters many such
   patterns; several new ones that were slipping past the filters are
   now blocked.)

 A hostile user that can create a publicly-readable file named
   "prefs.lang" somewhere on the Apache/PHP server can cause that file
   to be executed as PHP code.  The IMP configuration files could thus
   be read, the Horde database password used to read and alter the
   database used to store contacts and preferences, etc.  We do not
   believe this is remotely exploitable directly through Apache/PHP/IMP;
   however, shell access to the server or other means (e.g., FTP) could
   be used to create this file.



This has been fixed in version 2:2.2.6-0.potato.1. Please note that you
will also need to upgrade the horde package to the same version.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-073');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-073
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA073] DSA-073-1 imp");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-073-1 imp");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'horde', release: '2.2', reference: '1.2.6-0.potato.1');
deb_check(prefix: 'imp', release: '2.2', reference: '2.2.6-0.potato.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
