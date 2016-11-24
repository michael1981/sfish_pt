# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200601-04.xml
# It is released under the Nessus Script Licence.
# The messages are release under the Creative Commons - Attribution /
# Share Alike license. See http://creativecommons.org/licenses/by-sa/2.0/
#
# Avisory is copyright 2001-2006 Gentoo Foundation, Inc.
# GLSA2nasl Convertor is copyright 2004-2009 Tenable Network Security, Inc.

if (! defined_func('bn_random')) exit(0);

include('compat.inc');

if (description)
{
 script_id(20414);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200601-04");
 script_cve_id("CVE-2005-4459");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200601-04 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200601-04
(VMware Workstation: Vulnerability in NAT networking)


    Tim Shelton discovered that vmnet-natd, the host module providing
    NAT-style networking for VMware guest operating systems, is unable to
    process incorrect \'EPRT\' and \'PORT\' FTP requests.
  
Impact

    Malicious guest operating systems using the NAT networking feature or
    local VMware Workstation users could exploit this vulnerability to
    execute arbitrary code on the host system with elevated privileges.
  
Workaround

    Disable the NAT service by following the instructions at http://www.vmware.com/support/k
    b, Answer ID 2002.
  
');
script_set_attribute(attribute:'solution', value: '
    All VMware Workstation users should upgrade to a fixed version:
    # emerge --sync
    # emerge --ask --oneshot --verbose app-emulation/vmware-workstation
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://www.vmware.com/support/kb');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-4459');
script_set_attribute(attribute: 'see_also', value: 'http://www.vmware.com/support/kb/enduser/std_adp.php?p_faqid=2000');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200601-04.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200601-04] VMware Workstation: Vulnerability in NAT networking');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VMware Workstation: Vulnerability in NAT networking');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/vmware-workstation", unaffected: make_list("ge 5.5.1.19175", "rge 4.5.3.19414", "rge 3.2.1.2242-r10"), vulnerable: make_list("lt 5.5.1.19175")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
