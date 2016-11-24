# This script was automatically generated from the dsa-1812
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(39333);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1812");
 script_cve_id("CVE-2009-0023");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1812 security update');
 script_set_attribute(attribute: 'description', value:
'Apr-util, the Apache Portable Runtime Utility library, is used by
Apache 2.x, Subversion, and other applications. Two denial of service
vulnerabilities have been found in apr-util:
"kcope" discovered a flaw in the handling of internal XML entities in
the apr_xml_* interface that can be exploited to use all available
memory. This denial of service can be triggered remotely in the Apache
mod_dav and mod_dav_svn modules. (No CVE id yet)
CVE-2009-0023
Matthew Palmer discovered an underflow flaw in the
apr_strmatch_precompile function that can be exploited to cause a
daemon crash. The vulnerability can be triggered (1) remotely in
mod_dav_svn for Apache if the "SVNMasterURI" directive is in use, (2)
remotely in mod_apreq2 for Apache or other applications using
libapreq2, or (3) locally in Apache by a crafted ".htaccess" file.

Other exploit paths in other applications using apr-util may exist.
If you use Apache, or if you use svnserve in standalone mode, you need
to restart the services after you upgraded the libaprutil1 package.
The oldstable distribution (etch), these problems have been fixed in
version 1.2.7+dfsg-2+etch2.
For the stable distribution (lenny), these problems have been fixed in
version 1.2.12+dfsg-8+lenny2.
');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2009/dsa-1812');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your apr-util packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1812] DSA-1812-1 apr-util");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1812-1 apr-util");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'libaprutil1', release: '4.0', reference: '1.2.7+dfsg-2+etch2');
deb_check(prefix: 'libaprutil1-dbg', release: '4.0', reference: '1.2.7+dfsg-2+etch2');
deb_check(prefix: 'libaprutil1-dev', release: '4.0', reference: '1.2.7+dfsg-2+etch2');
deb_check(prefix: 'libaprutil1', release: '5.0', reference: '1.2.12+dfsg-8+lenny2');
deb_check(prefix: 'libaprutil1-dbg', release: '5.0', reference: '1.2.12+dfsg-8+lenny2');
deb_check(prefix: 'libaprutil1-dev', release: '5.0', reference: '1.2.12+dfsg-8+lenny2');
deb_check(prefix: 'apr-util', release: '5.0', reference: '1.2.12+dfsg-8+lenny2');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
