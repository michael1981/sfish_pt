# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200712-10.xml
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
 script_id(29297);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200712-10");
 script_cve_id("CVE-2007-6015");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200712-10 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200712-10
(Samba: Execution of arbitrary code)


    Alin Rad Pop (Secunia Research) discovered a boundary checking error in
    the send_mailslot() function which could lead to a stack-based buffer
    overflow.
  
Impact

    A remote attacker could send a specially crafted "SAMLOGON" domain
    logon packet, possibly leading to the execution of arbitrary code with
    elevated privileges. Note that this vulnerability is exploitable only
    when domain logon support is enabled in Samba, which is not the case in
    Gentoo\'s default configuration.
  
Workaround

    Disable domain logon in Samba by setting "domain logons = no" in
    the "global" section of your smb.conf and restart Samba.
  
');
script_set_attribute(attribute:'solution', value: '
    All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.28"
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6015');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200712-10.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200712-10] Samba: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.28"), vulnerable: make_list("lt 3.0.28")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
