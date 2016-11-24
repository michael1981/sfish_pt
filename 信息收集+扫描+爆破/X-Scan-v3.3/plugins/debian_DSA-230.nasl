# This script was automatically generated from the dsa-230
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15067);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "230");
 script_cve_id("CVE-2003-0012", "CVE-2003-0013");
 script_bugtraq_id(6501, 6502);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-230 security update');
 script_set_attribute(attribute: 'description', value:
'Two vulnerabilities have been discovered in Bugzilla, a web-based bug
tracking system, by its authors.  The Common Vulnerabilities and
Exposures Project identifies the following vulnerabilities:
  
   The provided data collection
   script intended to be run as a nightly cron job changes the
   permissions of the data/mining directory to be world-writable every
   time it runs.  This would enable local users to alter or delete the
   collected data.
  
  
   The default .htaccess scripts
   provided by checksetup.pl do not block access to backups of the
   localconfig file that might be created by editors such as vi or
   emacs (typically these will have a .swp or ~ suffix).  This allows
   an end user to download one of the backup copies and potentially
   obtain your database password.
  
  
   This does not affect the Debian installation because there is no
   .htaccess as all data file aren\'t under the CGI path as they are on
   the standard Bugzilla package.  Additionally, the configuration is
   in /etc/bugzilla/localconfig and hence outside of the web directory.
For the current stable distribution (woody) these problems have been
fixed in version 2.14.2-0woody4.
The old stable distribution (potato) does not contain a Bugzilla
package.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-230');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your bugzilla packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA230] DSA-230-1 bugzilla");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-230-1 bugzilla");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'bugzilla', release: '3.0', reference: '2.14.2-0woody4');
deb_check(prefix: 'bugzilla-doc', release: '3.0', reference: '2.14.2-0woody4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
