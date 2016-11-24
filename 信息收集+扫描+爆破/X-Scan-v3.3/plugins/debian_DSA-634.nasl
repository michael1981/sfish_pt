# This script was automatically generated from the dsa-634
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(16131);
 script_version("$Revision: 1.8 $");
 script_xref(name: "DSA", value: "634");
 script_cve_id("CVE-2004-1182");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-634 security update');
 script_set_attribute(attribute: 'description', value:
'Patrice Fournier discovered a vulnerability in the authorisation
subsystem of hylafax, a flexible client/server fax system.  A local or
remote user guessing the contents of the hosts.hfaxd database could
gain unauthorised access to the fax system.
Some installations of hylafax may actually utilise the weak hostname
and username validation for authorized uses.  For example, hosts.hfaxd
entries that may be common are

  192.168.0
  username:uid:pass:adminpass
  user@host


After updating, these entries will need to be modified in order to
continue to function.  Respectively, the correct entries should be

  192.168.0.[0-9]+
  username@:uid:pass:adminpass
  user@host


Unless such matching of "username" with "otherusername" and "host" with
"hostname" is desired, the proper form of these entries should include
the delimiter and markers like this

  @192.168.0.[0-9]+$
  ^username@:uid:pass:adminpass
  ^user@host$


For the stable distribution (woody) this problem has been fixed in
version 4.1.1-3.1.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2005/dsa-634');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your hylafax packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA634] DSA-634-1 hylafax");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-634-1 hylafax");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'hylafax-client', release: '3.0', reference: '4.1.1-3.1');
deb_check(prefix: 'hylafax-doc', release: '3.0', reference: '4.1.1-3.1');
deb_check(prefix: 'hylafax-server', release: '3.0', reference: '4.1.1-3.1');
deb_check(prefix: 'hylafax', release: '3.0', reference: '4.1.1-3.1');
if (deb_report_get()) security_hole(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
