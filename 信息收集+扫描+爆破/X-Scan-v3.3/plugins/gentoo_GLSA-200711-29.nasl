# This script was automatically generated from 
#  http://www.gentoo.org/security/en/glsa/glsa-200711-29.xml
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
 script_id(28318);
 script_version("$Revision: 1.4 $");
 script_xref(name: "GLSA", value: "200711-29");
 script_cve_id("CVE-2007-4572", "CVE-2007-5398");

 script_set_attribute(attribute:'synopsis', value: 'The remote host is missing the GLSA-200711-29 security update.');
 script_set_attribute(attribute:'description', value: 'The remote host is affected by the vulnerability described in GLSA-200711-29
(Samba: Execution of arbitrary code)


    Two vulnerabilities have been reported in nmbd. Alin Rad Pop (Secunia
    Research) discovered a boundary checking error in the
    reply_netbios_packet() function which could lead to a stack-based
    buffer overflow (CVE-2007-5398). The Samba developers discovered a
    boundary error when processing GETDC logon requests also leading to a
    buffer overflow (CVE-2007-4572).
  
Impact

    To exploit the first vulnerability, a remote unauthenticated attacker
    could send specially crafted WINS "Name Registration" requests followed
    by a WINS "Name Query" request. This might lead to execution of
    arbitrary code with elevated privileges. Note that this vulnerability
    is exploitable only when WINS server support is enabled in Samba. The
    second vulnerability could be exploited by sending specially crafted
    "GETDC" mailslot requests, but requires Samba to be configured as a
    Primary or Backup Domain Controller. It is not believed the be
    exploitable to execute arbitrary code.
  
Workaround

    To work around the first vulnerability, disable WINS support in Samba
    by setting "wins support = no" in the "global" section of your
    smb.conf and restart Samba.
  
');
script_set_attribute(attribute:'solution', value: '
    All Samba users should upgrade to the latest version:
    # emerge --sync
    # emerge --ask --oneshot --verbose ">=net-fs/samba-3.0.27a"
    The first vulnerability (CVE-2007-5398) was already fixed in Samba
    3.0.26a-r2.
  ');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4572');
script_set_attribute(attribute: 'see_also', value: 'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-5398');

script_set_attribute(attribute: 'see_also', value: 'http://www.gentoo.org/security/en/glsa/glsa-200711-29.xml');

script_end_attributes();

 script_copyright(english: "(C) 2009 Tenable Network Security, Inc.");
 script_name(english: '[GLSA-200711-29] Samba: Execution of arbitrary code');
 script_category(ACT_GATHER_INFO);
 script_family(english: "Gentoo Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys('Host/Gentoo/qpkg-list');
 script_summary(english: 'Samba: Execution of arbitrary code');
 exit(0);
}

include('qpkg.inc');

if ( ! get_kb_item('Host/Gentoo/qpkg-list') ) exit(1, 'No list of packages');
if (qpkg_check(package: "net-fs/samba", unaffected: make_list("ge 3.0.27a"), vulnerable: make_list("lt 3.0.27a")
)) { security_hole(0); exit(0); }
exit(0, "Host is not affected");
