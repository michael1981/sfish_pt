# This script was automatically generated from the dsa-404
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(15241);
 script_version("$Revision: 1.12 $");
 script_xref(name: "DSA", value: "404");
 script_cve_id("CVE-2003-0962");
 script_bugtraq_id(9153);

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-404 security update');
 script_set_attribute(attribute: 'description', value:
'The rsync team has received evidence that a vulnerability in all
versions of rsync prior to 2.5.7, a fast remote file copy program, was
recently used in combination with a Linux kernel vulnerability to
compromise the security of a public rsync server.
While this heap overflow vulnerability could not be used by itself to
obtain root access on an rsync server, it could be used in combination
with the recently announced do_brk() vulnerability in the Linux kernel
to produce a full remote compromise.
Please note that this vulnerability only affects the use of rsync as
an "rsync server".  To see if you are running a rsync server you
should use the command "netstat -a -n" to see if you are listening on
TCP port 873.  If you are not listening on TCP port 873 then you are
not running an rsync server.
For the stable distribution (woody) this problem has been fixed in
version 2.5.5-0.2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2003/dsa-404');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your rsync package immediately if you
are providing remote sync services.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA404] DSA-404-1 rsync");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-404-1 rsync");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'rsync', release: '3.0', reference: '2.5.5-0.2');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
