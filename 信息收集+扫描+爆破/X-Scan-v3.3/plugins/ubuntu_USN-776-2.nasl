# This script was automatically generated from the 776-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38777);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "776-2");
script_summary(english:"kvm regression");
script_name(english:"USN776-2 : kvm regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kvm 
- kvm-source 
');
script_set_attribute(attribute:'description', value: 'USN-776-1 fixed vulnerabilities in KVM. Due to an incorrect fix, a
regression was introduced in Ubuntu 8.04 LTS that caused KVM to fail to
boot virtual machines started via libvirt. This update fixes the problem.
We apologize for the inconvenience.

Original advisory details:

 Avi Kivity discovered that KVM did not correctly handle certain disk
 formats. A local attacker could attach a malicious partition that would
 allow the guest VM to read files on the VM host. (CVE-2008-1945,
 CVE-2008-2004)

 Alfredo Ortega discovered that KVM\'s VNC protocol handler did not
 correctly validate certain messages. A remote attacker could send
 specially crafted VNC messages that would cause KVM to consume CPU
 resources, leading to a denial of service. (CVE-2008-2382)

 Jan Niehusmann discovered that KVM\'s Cirrus VGA implementation over VNC
 did not correctly handle certain bitblt operations. A local attacker could
 exploit this flaw to potentially execute arbitrary code on the VM host or
 crash KVM, leading to a denia
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kvm-62+dfsg-0ubuntu8.2 (Ubuntu 8.04)
- kvm-source-62+dfsg-0ubuntu8.2 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2008-1945","CVE-2008-2004","CVE-2008-2382","CVE-2008-4539","CVE-2008-5714");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "kvm", pkgver: "62+dfsg-0ubuntu8.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kvm-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kvm-62+dfsg-0ubuntu8.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "kvm-source", pkgver: "62+dfsg-0ubuntu8.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kvm-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kvm-source-62+dfsg-0ubuntu8.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
