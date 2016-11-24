# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200502-18.xml
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
 script_id(16459);
 script_version("$Revision: 1.5 $");
 script_xref(name: "GLSA", value: "200502-18");
 script_cve_id("CVE-2005-0444");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200502-18 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200502-18
(VMware Workstation: Untrusted library search path)


    Tavis Ormandy of the Gentoo Linux Security Audit Team has discovered
    that VMware Workstation searches for gdk-pixbuf loadable modules in an
    untrusted, world-writable directory.
  
Impact

    A local attacker could create a malicious shared object that would be
    loaded by VMware, resulting in the execution of arbitrary code with the
    privileges of the user running VMware.
  
Workaround

    The system administrator may create the file /tmp/rrdharan to prevent
    malicious users from creating a directory at that location:
    # touch /tmp/rrdharan
  
');
script_set_attribute(attribute:'solution', value: '
    All VMware Workstation users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=app-emulation/vmware-workstation-3.2.1.2242-r4"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0444');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200502-18.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200502-18] VMware Workstation: Untrusted library search path');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'VMware Workstation: Untrusted library search path');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "app-emulation/vmware-workstation", unaffected: make_list("ge 4.5.2.8848-r5", "rge 3.2.1.2242-r4"), vulnerable: make_list("lt 4.5.2.8848-r5")
)) { security_warning(0); exit(0); }
exit(0, "Host is not affected");
