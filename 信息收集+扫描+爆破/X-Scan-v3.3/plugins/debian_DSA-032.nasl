# This script was automatically generated from the dsa-032
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14869);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "032");
 script_cve_id("CVE-2001-0456");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-032 security update');
 script_set_attribute(attribute: 'description', value:
'The following problems have been reported for the version
of proftpd in Debian 2.2 (potato):


There is a configuration error in the postinst script, when the user enters
\'yes\', when asked if anonymous access should be enabled.  The postinst script
wrongly leaves the \'run as uid/gid root\' configuration option in
/etc/proftpd.conf, and adds a \'run as uid/gid nobody\' option that has no
effect.
There is a bug that comes up when /var is a symlink, and proftpd is
restarted. When stopping proftpd, the /var symlink is removed; when it\'s
started again a file named /var is created.


The above problems have been corrected in proftpd-1.2.0pre10-2.0potato1.  We
recommend you upgrade your proftpd package immediately.  
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-032');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-032
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA032] DSA-032-1 proftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-032-1 proftpd");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'proftpd', release: '2.2', reference: '1.2.0pre10-2.0potato1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
