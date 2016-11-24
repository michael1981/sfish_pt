# This script was automatically generated from the dsa-1617
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2009 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description) {
 script_id(33737);
 script_version("$Revision: 1.3 $");
 script_xref(name: "DSA", value: "1617");
 script_cve_id("CVE-2008-1447");

 script_set_attribute(attribute:'synopsis', value: 
'The remote host is missing the DSA-1617 security update');
 script_set_attribute(attribute: 'description', value:
'In DSA-1603-1, Debian released an update to the BIND 9 domain name
server, which introduced UDP source port randomization to mitigate
the threat of DNS cache poisoning attacks (identified by the Common
Vulnerabilities and Exposures project as CVE-2008-1447).
The fix, while correct, was incompatible with the version of SELinux Reference
Policy shipped with Debian Etch, which did not permit a process running in the
named_t domain to bind sockets to UDP ports other than the standard \'domain\'
port (53).
The incompatibility affects both the \'targeted\' and \'strict\' policy packages
supplied by this version of refpolicy.


This update to the refpolicy packages grants the ability to bind to
arbitrary UDP ports to named_t processes.
When installed, the updated packages will attempt to update the bind policy
module on systems where it had been previously loaded and where the previous
version of refpolicy was 0.0.20061018-5 or below.


Because the Debian refpolicy packages are not yet designed with policy module
upgradeability in mind, and because SELinux-enabled Debian systems often have
some degree of site-specific policy customization, it is difficult to assure
that the new bind policy can be successfully upgraded.
To this end, the package upgrade will not abort if the bind policy update
fails.
The new policy module can be found at
/usr/share/selinux/refpolicy-targeted/bind.pp after installation.
Administrators wishing to use the bind service policy can reconcile any policy
incompatibilities and install the upgrade manually thereafter.
A more detailed discussion of the corrective procedure may be found on
http://wiki.debian.org/SELinux/Issues/BindPortRandomization.

For the stable distribution (etch), this problem has been fixed in
version 0.0.20061018-5.1+etch1.

');
 script_set_attribute(attribute: 'see_also', value: 
'http://www.debian.org/security/2008/dsa-1617');
 script_set_attribute(attribute: 'solution', value: 
'The Debian project recommends that you upgrade your refpolicy packages.');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

 script_copyright(english: "This script is (C) 2009 Tenable Network Security, Inc.");
 script_name(english: "[DSA1617] DSA-1617-1 refpolicy");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1617-1 refpolicy");
 exit(0);
}

include("debian_package.inc");

if ( ! get_kb_item("Host/Debian/dpkg-l") ) exit(1, "Could not obtain the list of packages");

deb_check(prefix: 'selinux-policy-refpolicy-dev', release: '4.0', reference: '0.0.20061018-5.1+etch1');
deb_check(prefix: 'selinux-policy-refpolicy-doc', release: '4.0', reference: '0.0.20061018-5.1+etch1');
deb_check(prefix: 'selinux-policy-refpolicy-src', release: '4.0', reference: '0.0.20061018-5.1+etch1');
deb_check(prefix: 'selinux-policy-refpolicy-strict', release: '4.0', reference: '0.0.20061018-5.1+etch1');
deb_check(prefix: 'selinux-policy-refpolicy-targeted', release: '4.0', reference: '0.0.20061018-5.1+etch1');
deb_check(prefix: 'refpolicy', release: '4.0', reference: '0.0.20061018-5.1+etch1');
if (deb_report_get()) security_warning(port: 0, extra:deb_report_get());
else exit(0, "Host is not affected");
