# This script was automatically generated from the dsa-065
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14902);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "065");
 script_cve_id("CVE-2001-1162");
 script_bugtraq_id(2927);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-065 security update');
 script_set_attribute(attribute: 'description', value:
'Michal Zalewski discovered that Samba does not properly validate
NetBIOS names from remote machines.

By itself that is not a problem, except if Samba is configured to
write log-files to a file that includes the NetBIOS name of the
remote side by using the `%m\' macro in the `log file\' command. In
that case an attacker could use a NetBIOS name like \'../tmp/evil\'.
If the log-file was set to "/var/log/samba/%s" Samba would then
write to /var/tmp/evil.

Since the NetBIOS name is limited to 15 characters and the `log
file\' command could have an extension to the filename the results
of this are limited. However if the attacker is also able to create
symbolic links on the Samba server they could trick Samba into
appending any data they want to all files on the filesystem which
Samba can write to.

The Debian GNU/Linux packaged version of Samba has a safe
configuration and is not vulnerable.

As temporary workaround for systems that are vulnerable change all
occurrences of the `%m\' macro in smb.conf to `%l\' and restart Samba.

This has been fixed in version 2.0.7-3.4, and we recommend that you
upgrade your Samba package immediately.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-065');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-065
and install the recommended updated packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA065] DSA-065-1 samba");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-065-1 samba");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'samba', release: '2.2', reference: '2.0.7-3.4');
deb_check(prefix: 'samba-common', release: '2.2', reference: '2.0.7-3.4');
deb_check(prefix: 'samba-doc', release: '2.2', reference: '2.0.7-3.4');
deb_check(prefix: 'smbclient', release: '2.2', reference: '2.0.7-3.4');
deb_check(prefix: 'smbfs', release: '2.2', reference: '2.0.7-3.4');
deb_check(prefix: 'swat', release: '2.2', reference: '2.0.7-3.4');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
