# This script was automatically generated from the dsa-044
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(14881);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "044");
 script_bugtraq_id(2457);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-044 security update');
 script_set_attribute(attribute: 'description', value:
'The mail program (a simple tool to read and send
email) as distributed with Debian GNU/Linux 2.2 has a buffer overflow
in the input parsing code. Since mail is installed setgid mail by
default this allowed local users to use it to gain access to mail
group.

Since the mail code was never written to be secure fixing it
properly would mean a large rewrite. Instead of doing this we decided
to no longer install it setgid. This means that it can no longer lock
your mailbox properly on systems for which you need group mail to
write to the mailspool, but it will still work for sending email.

This has been fixed in mailx version 8.1.1-10.1.5. If you have
suidmanager installed you can also make this manually with the
following command:
suidregister /usr/bin/mail root root 0755

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2001/dsa-044');
 script_set_attribute(attribute: 'solution', value: 
'Read http://www.debian.org/security/2001/dsa-044
and install the recommended updated packages.');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA044] DSA-044-1 mailx");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-044-1 mailx");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'mailx', release: '2.2', reference: '8.1.1-10.1.5');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
